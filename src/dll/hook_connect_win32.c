// SPDX-License-Identifier: GPL-2.0-or-later
/* hook_connect_win32.c
 * Copyright (C) 2020 Feng Shun.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2 as 
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License version 2 for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   version 2 along with this program. If not, see
 *   <http://www.gnu.org/licenses/>.
 */
#define PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#define PXCH_INCLUDE_WINSOCK_UTIL
#include "includes_win32.h"
#define PXCH_CONST_TLS_SIZE_COMPILE_TIME_WIN32_NEEDED
#include "tls_generic.h"
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Mswsock.h>
#include <Shlwapi.h>
#include <stdlib.h>
#include <strsafe.h>
#include "hookdll_util_win32.h"
#include "log_generic.h"
#include "tls_win32.h"
#include <MinHook.h>

#include "proxy_core.h"
#include "hookdll_win32.h"

#ifndef __CYGWIN__
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")
#endif

static PXCH_PROXY_DIRECT_DATA g_proxyDirect;

static char pHostentPseudoTls[PXCH_TLS_END_W32HOSTENT];

typedef struct _PXCH_WS2_32_TEMP_DATA {
	DWORD iConnectLastError;
	int iConnectWSALastError;
	int iOriginalAddrFamily;
	int iConnectReturn;
} PXCH_WS2_32_TEMP_DATA;

typedef struct _PXCH_MSWSOCK_TEMP_DATA {
	DWORD iConnectLastError;
	int iConnectWSALastError;
	int iOriginalAddrFamily;
	BOOL bConnectReturn;
} PXCH_MSWSOCK_TEMP_DATA;

typedef union _PXCH_TEMP_DATA {
	struct {
		DWORD iConnectLastError;
		int iConnectWSALastError;
		int iOriginalAddrFamily;
	} CommonHeader;
	PXCH_MSWSOCK_TEMP_DATA Mswsock_TempData;
	PXCH_WS2_32_TEMP_DATA Ws2_32_TempData;
} PXCH_TEMP_DATA;

static BOOL ResolveByHostsFile(PXCH_IP_ADDRESS* pIp, const PXCH_HOSTNAME* pHostname, int iFamily)
{
	PXCH_UINT32 i;
	PXCH_IP_ADDRESS* pCurrentIp;

	for (i = 0; i < g_pPxchConfig->dwHostsEntryNum; i++) {
		if (StrCmpW(PXCH_CONFIG_HOSTS_ENTRY_ARR_G[i].Hostname.szValue, pHostname->szValue) == 0) {
			pCurrentIp = &PXCH_CONFIG_HOSTS_ENTRY_ARR_G[i].Ip;
			if (iFamily == AF_UNSPEC
				|| (iFamily == AF_INET && pCurrentIp->CommonHeader.wTag == PXCH_HOST_TYPE_IPV4)
				|| (iFamily == AF_INET6 && pCurrentIp->CommonHeader.wTag == PXCH_HOST_TYPE_IPV6)
			) {
				if (pIp) *pIp = *pCurrentIp;
				break;
			}
		}
	}
	return i != g_pPxchConfig->dwHostsEntryNum;
}

static BOOL Ipv4MatchCidr(const struct sockaddr_in* pIp, const struct sockaddr_in* pCidr, DWORD dwCidrPrefixLength)
{
	// long is always 32-bit
	PXCH_UINT32 dwMask = htonl(~(((PXCH_UINT64)1 << (32 - dwCidrPrefixLength)) - 1));

	return (pIp->sin_addr.s_addr & dwMask) == (pCidr->sin_addr.s_addr & dwMask);
}

static BOOL Ipv6MatchCidr(const struct sockaddr_in6* pIp, const struct sockaddr_in6* pCidr, DWORD dwCidrPrefixLength)
{
	struct {
		PXCH_UINT64 First64;
		PXCH_UINT64 Last64;
	} MaskInvert, MaskedIpv6, MaskedCidr, * pIpv6AddrInQwords;

	PXCH_UINT32 dwToShift = dwCidrPrefixLength > 128 ? 0 : 128 - dwCidrPrefixLength;
	PXCH_UINT32 dwShift1 = dwToShift >= 64 ? 64 : dwToShift;
	PXCH_UINT32 dwShift2 = dwToShift >= 64 ? (dwToShift - 64) : 0;

	MaskInvert.Last64 = dwShift1 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift1) - 1);
	MaskInvert.First64 = dwShift2 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift2) - 1);

	if (LITTLEENDIAN) {
		MaskInvert.Last64 = _byteswap_uint64(MaskInvert.Last64);
		MaskInvert.First64 = _byteswap_uint64(MaskInvert.First64);
	}

	pIpv6AddrInQwords = (void*)&pIp->sin6_addr;
	MaskedIpv6 = *pIpv6AddrInQwords;
	MaskedIpv6.First64 &= ~MaskInvert.First64;
	MaskedIpv6.Last64 &= ~MaskInvert.Last64;

	pIpv6AddrInQwords = (void*)&pCidr->sin6_addr;
	MaskedCidr = *pIpv6AddrInQwords;
	MaskedCidr.First64 &= ~MaskInvert.First64;
	MaskedCidr.Last64 &= ~MaskInvert.Last64;

	// return RtlCompareMemory(&MaskedIpv6, &MaskedCidr, sizeof(MaskedIpv6)) == sizeof(MaskedIpv6);
	return memcmp(&MaskedIpv6, &MaskedCidr, sizeof(MaskedIpv6)) == 0;
}

static PXCH_UINT32 GetTargetByRule(BOOL* pbHasMatchedHostnameRule, BOOL* pbMatchedIpRule, BOOL* pbMatchedPortRule, BOOL* pbMatchedFinalRule, const PXCH_HOST_PORT* pHostPort)
{
	unsigned int i;
	PXCH_RULE* pRule;
	BOOL bDummyMatched1;
	BOOL bDummyMatched2;
	BOOL bDummyMatched3;
	BOOL bDummyMatched4;

	if (pbHasMatchedHostnameRule == NULL) pbHasMatchedHostnameRule = &bDummyMatched1;
	if (pbMatchedIpRule == NULL) pbMatchedIpRule = &bDummyMatched2;
	if (pbMatchedPortRule == NULL) pbMatchedPortRule = &bDummyMatched3;
	if (pbMatchedFinalRule == NULL) pbMatchedFinalRule = &bDummyMatched4;

	*pbHasMatchedHostnameRule = FALSE;
	*pbMatchedIpRule = FALSE;
	*pbMatchedPortRule = FALSE;
	*pbMatchedFinalRule = FALSE;

	for (i = 0; i < g_pPxchConfig->dwRuleNum; i++) {
		pRule = &PXCH_CONFIG_RULE_ARR(g_pPxchConfig)[i];

		if (RuleIsType(FINAL, *pRule)) {
			return pRule->dwTarget;
		}

		if (pRule->HostPort.CommonHeader.wPort && pHostPort->CommonHeader.wPort) {
			if (pRule->HostPort.CommonHeader.wPort != pHostPort->CommonHeader.wPort) {
				// Mismatch
				continue;
			}
			else if (RuleIsType(PORT, *pRule)) {
				// Match
				*pbMatchedPortRule = TRUE;
				return pRule->dwTarget;
			}
		}

		if (HostIsIp(*pHostPort) && RuleIsType(IP_CIDR, *pRule)) {
			if (HostIsType(IPV4, *pHostPort) && HostIsType(IPV4, pRule->HostPort)) {
				const struct sockaddr_in* pIpv4 = (const struct sockaddr_in*)pHostPort;
				const struct sockaddr_in* pRuleIpv4 = (const struct sockaddr_in*) & pRule->HostPort;

				if (Ipv4MatchCidr(pIpv4, pRuleIpv4, pRule->dwCidrPrefixLength))
				 {
					// Match
					*pbMatchedIpRule = TRUE;
					return pRule->dwTarget;
				}
			}

			if (HostIsType(IPV6, *pHostPort) && HostIsType(IPV6, pRule->HostPort)) {
				const struct sockaddr_in6* pIpv6 = (const struct sockaddr_in6*)pHostPort;
				const struct sockaddr_in6* pRuleIpv6 = (const struct sockaddr_in6*) & pRule->HostPort;

				if (Ipv6MatchCidr(pIpv6, pRuleIpv6, pRule->dwCidrPrefixLength)) {
					// Match
					*pbMatchedIpRule = TRUE;
					return pRule->dwTarget;
				}
			}
		}

		if (HostIsType(HOSTNAME, *pHostPort) && RuleIsType(DOMAIN, *pRule)) {
			if (StrCmpIW(pHostPort->HostnamePort.szValue, pRule->HostPort.HostnamePort.szValue) == 0) {
				// Match
				*pbHasMatchedHostnameRule = TRUE;
				return pRule->dwTarget;
			}
		}

		if (HostIsType(HOSTNAME, *pHostPort) && RuleIsType(DOMAIN_SUFFIX, *pRule)) {
			size_t cchLength = 0;
			size_t cchRuleLength = 0;
			StringCchLengthW(pHostPort->HostnamePort.szValue, _countof(pHostPort->HostnamePort.szValue), &cchLength);
			StringCchLengthW(pRule->HostPort.HostnamePort.szValue, _countof(pRule->HostPort.HostnamePort.szValue), &cchRuleLength);

			if (cchRuleLength <= cchLength) {
				if (StrCmpIW(pHostPort->HostnamePort.szValue + (cchLength - cchRuleLength), pRule->HostPort.HostnamePort.szValue) == 0) {
					// Match
					*pbHasMatchedHostnameRule = TRUE;
					return pRule->dwTarget;
				}
			}
		}

		if (HostIsType(HOSTNAME, *pHostPort) && RuleIsType(DOMAIN_KEYWORD, *pRule)) {
			if (pRule->HostPort.HostnamePort.szValue[0] == L'\0' || StrStrIW(pHostPort->HostnamePort.szValue, pRule->HostPort.HostnamePort.szValue)) {
				// Match
				*pbHasMatchedHostnameRule = TRUE;
				return pRule->dwTarget;
			}
		}
	}

	return g_pPxchConfig->dwDefaultTarget;
}

PXCH_UINT32 ReverseLookupForHost(PXCH_HOSTNAME_PORT* pReverseLookedupHostnamePort, PXCH_IP_PORT* pReverseLookedupResolvedIpPort, const PXCH_IP_PORT** ppIpPortForDirectConnection, const PXCH_HOST_PORT** ppHostPortForProxiedConnection, PXCH_UINT32* pdwTarget, const PXCH_IP_PORT* pOriginalIpPort, int iOriginalAddrLen)
{
	PXCH_IPC_MSGBUF chMessageBuf;
	PXCH_UINT32 cbMessageSize;
	PXCH_IPC_MSGBUF chRespMessageBuf;
	PXCH_UINT32 cbRespMessageSize;
	PXCH_IP_ADDRESS ReqIp;
	PXCH_IP_ADDRESS RespIps[PXCH_MAX_ARRAY_IP_NUM];
	PXCH_UINT32 dwRespIpNum;
	PXCH_HOSTNAME EmptyHostname = { 0 };
	DWORD dwLastError;
	DWORD dw;

	if ((HostIsType(IPV4, *pOriginalIpPort) 
			&& Ipv4MatchCidr(
				(const struct sockaddr_in*)pOriginalIpPort,
				(const struct sockaddr_in*)&g_pPxchConfig->FakeIpv4Range,
				g_pPxchConfig->dwFakeIpv4PrefixLength))
		|| (HostIsType(IPV6, *pOriginalIpPort)
			&& Ipv6MatchCidr(
				(const struct sockaddr_in6*)pOriginalIpPort,
				(const struct sockaddr_in6*)&g_pPxchConfig->FakeIpv6Range,
				g_pPxchConfig->dwFakeIpv6PrefixLength))) {
		
		// Fake Ip

		// Some application will pass OriginalIpPort with garbage in memory sections which ought to be zero, which will affect our reverse lookup
		ZeroMemory(&ReqIp, sizeof(PXCH_IP_ADDRESS));
		ReqIp.CommonHeader.wTag = pOriginalIpPort->CommonHeader.wTag;
		if (HostIsType(IPV4, ReqIp)) {
			((struct sockaddr_in*)&ReqIp)->sin_addr = ((struct sockaddr_in*)pOriginalIpPort)->sin_addr;
		} else if (HostIsType(IPV6, ReqIp)) {
			((struct sockaddr_in6*)&ReqIp)->sin6_addr = ((struct sockaddr_in6*)pOriginalIpPort)->sin6_addr;
			((struct sockaddr_in6*)&ReqIp)->sin6_flowinfo = ((struct sockaddr_in6*)pOriginalIpPort)->sin6_flowinfo;
			((struct sockaddr_in6*)&ReqIp)->sin6_scope_id = ((struct sockaddr_in6*)pOriginalIpPort)->sin6_scope_id;
			((struct sockaddr_in6*)&ReqIp)->sin6_scope_struct = ((struct sockaddr_in6*)pOriginalIpPort)->sin6_scope_struct;
		}
		ReqIp.CommonHeader.wPort = 0;

		if ((dwLastError = HostnameAndIpsToMessage(chMessageBuf, &cbMessageSize, GetCurrentProcessId(), &EmptyHostname, FALSE /*ignored*/, 1, &ReqIp, FALSE /*ignored*/)) != NO_ERROR) goto err_general;

		if ((dwLastError = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, (PXCH_UINT32*)&cbRespMessageSize)) != NO_ERROR) goto err_general;

		if ((dwLastError = MessageToHostnameAndIps(NULL, (PXCH_HOSTNAME*)pReverseLookedupHostnamePort, NULL, &dwRespIpNum, RespIps, pdwTarget, chRespMessageBuf, cbRespMessageSize)) != NO_ERROR) goto err_general;

		for (dw = 0; dw < dwRespIpNum; dw++) {
			if (RespIps[dw].CommonHeader.wTag == pOriginalIpPort->CommonHeader.wTag) {
				break;
			}
		}
		// if (dw == dwRespIpNum) goto addr_not_supported_end;
		if (dw != dwRespIpNum) {
			*pReverseLookedupResolvedIpPort = RespIps[dw];
			pReverseLookedupResolvedIpPort->CommonHeader.wPort = pOriginalIpPort->CommonHeader.wPort;
			*ppIpPortForDirectConnection = pReverseLookedupResolvedIpPort;
		} else {
			ZeroMemory(pReverseLookedupResolvedIpPort, sizeof(PXCH_IP_PORT));
			*ppIpPortForDirectConnection = NULL;
		}

		pReverseLookedupHostnamePort->wPort = pOriginalIpPort->CommonHeader.wPort;
		*ppHostPortForProxiedConnection = (const PXCH_HOST_PORT*)pReverseLookedupHostnamePort;

		// Case for entry not found
		if (pReverseLookedupHostnamePort->szValue[0] == L'\0') {
			*pdwTarget = GetTargetByRule(NULL, NULL, NULL, NULL, (const PXCH_HOST_PORT*)*ppIpPortForDirectConnection);
		}
	} else {
		*pdwTarget = GetTargetByRule(NULL, NULL, NULL, NULL, (const PXCH_HOST_PORT*)pOriginalIpPort);
	}

	return NO_ERROR;

err_general:
	return dwLastError;
// addr_not_supported_end:
//	return ERROR_NOT_SUPPORTED;
}

void PrintConnectResultAndFreeResources(const WCHAR* szPrintPrefix, PXCH_UINT_PTR SocketHandle, const void* pOriginalAddr, int iOriginalAddrLen, const PXCH_IP_PORT* pIpPortForDirectConnection, const PXCH_HOST_PORT* pHostPortForProxiedConnection, PXCH_UINT32 dwTarget, PXCH_CHAIN* pChain, int iReturn, BOOL bIsConnectSuccessful, int iWSALastError)
{
	WCHAR chPrintBuf[256];
	WCHAR* pPrintBuf;
	PXCH_CHAIN_NODE* ChainNode = NULL;
	PXCH_CHAIN_NODE* TempChainNode1 = NULL;
	PXCH_CHAIN_NODE* TempChainNode2 = NULL;

	pPrintBuf = chPrintBuf;
	StringCchCopyExW(pPrintBuf, _countof(chPrintBuf) - (pPrintBuf - chPrintBuf), szPrintPrefix, &pPrintBuf, NULL, 0);

	StringCchPrintfExW(pPrintBuf, _countof(chPrintBuf) - (pPrintBuf - chPrintBuf), &pPrintBuf, NULL, 0, L"(%d %ls %d)", (unsigned long)SocketHandle, FormatHostPortToStr(pOriginalAddr, iOriginalAddrLen), iOriginalAddrLen);

	if (dwTarget == PXCH_RULE_TARGET_DIRECT && (const void*)pIpPortForDirectConnection != pOriginalAddr) {
		StringCchPrintfExW(pPrintBuf, _countof(chPrintBuf) - (pPrintBuf - chPrintBuf), &pPrintBuf, NULL, 0, L" -> %ls", FormatHostPortToStr(pIpPortForDirectConnection, iOriginalAddrLen));
	} else if (dwTarget == PXCH_RULE_TARGET_PROXY && HostIsType(HOSTNAME, *pHostPortForProxiedConnection)) {
		StringCchPrintfExW(pPrintBuf, _countof(chPrintBuf) - (pPrintBuf - chPrintBuf), &pPrintBuf, NULL, 0, L" -> %ls", FormatHostPortToStr(pHostPortForProxiedConnection, sizeof(PXCH_HOST_PORT)));
	} else if (dwTarget == PXCH_RULE_TARGET_BLOCK && (const void*)pIpPortForDirectConnection != pOriginalAddr && HostIsType(HOSTNAME, *pHostPortForProxiedConnection)) {
		StringCchPrintfExW(pPrintBuf, _countof(chPrintBuf) - (pPrintBuf - chPrintBuf), &pPrintBuf, NULL, 0, L" -> %ls", FormatHostPortToStr(pHostPortForProxiedConnection, sizeof(PXCH_HOST_PORT)));
	}

	StringCchPrintfExW(pPrintBuf, _countof(chPrintBuf) - (pPrintBuf - chPrintBuf), &pPrintBuf, NULL, 0, L" %ls", g_szRuleTargetDesc[dwTarget]);

	CDL_FOREACH_SAFE(*pChain, ChainNode, TempChainNode1, TempChainNode2) {
		CDL_DELETE(*pChain, ChainNode);
		HeapFree(GetProcessHeap(), 0, ChainNode);
	}
	if (!bIsConnectSuccessful && iWSALastError != WSAEWOULDBLOCK && !(iWSALastError == WSAEREFUSED && dwTarget == PXCH_RULE_TARGET_BLOCK)) {
		FUNCIPCLOGW(L"%ls ret: %d, wsa last error: %ls", chPrintBuf, iReturn, FormatErrorToStr(iWSALastError));
	} else {
		if (g_pPxchConfig->dwLogLevel < PXCH_LOG_LEVEL_DEBUG) {
			FUNCIPCLOGI(L"%ls", chPrintBuf);
		} else {
			FUNCIPCLOGD(L"%ls ret: %d, wsa last error: %ls", chPrintBuf, iReturn, FormatErrorToStr(iWSALastError));
		}
	}
}

int Ws2_32_OriginalConnect(void* pTempData, PXCH_UINT_PTR s, const void* pAddr, int iAddrLen)
{
	int iReturn;
	int iWSALastError;
	DWORD dwLastError;
	PXCH_WS2_32_TEMP_DATA* pWs2_32_TempData = pTempData;

	iReturn = orig_fpWs2_32_connect(s, pAddr, iAddrLen);
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();

	if (pWs2_32_TempData) {
		pWs2_32_TempData->iConnectReturn = iReturn;
		pWs2_32_TempData->iConnectWSALastError = iWSALastError;
		pWs2_32_TempData->iConnectLastError = dwLastError;
	}

	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iReturn;
}

int Ws2_32_BlockConnect(void* pTempData, PXCH_UINT_PTR s, const void* pAddr, int iAddrLen)
{
	int iReturn;
	int iWSALastError;
	DWORD dwLastError;
	fd_set wfds;
	PXCH_WS2_32_TEMP_DATA* pWs2_32_TempData = pTempData;
	TIMEVAL Timeout = {
		.tv_sec = g_pPxchConfig->dwProxyConnectionTimeoutMillisecond / 1000,
		.tv_usec = g_pPxchConfig->dwProxyConnectionTimeoutMillisecond * 1000
	};

	iReturn = orig_fpWs2_32_connect(s, pAddr, iAddrLen);
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();

	if (pWs2_32_TempData) {
		pWs2_32_TempData->iConnectReturn = iReturn;
		pWs2_32_TempData->iConnectWSALastError = iWSALastError;
		pWs2_32_TempData->iConnectLastError = dwLastError;
	}

	if (iReturn) {
		if (iWSALastError == WSAEWOULDBLOCK) {
			FUNCIPCLOGD(L"Ws2_32_BlockConnect(%d, %ls, %d) : this socket is nonblocking and connect() didn't finish instantly.", s, FormatHostPortToStr(pAddr, iAddrLen), iAddrLen);
		}
		else goto err_connect;
	}

	FD_ZERO(&wfds);
	FD_SET(s, &wfds);
	iReturn = select(-1, NULL, &wfds, NULL, &Timeout);
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();
	
	if (iReturn == 0) goto err_timeout;
	if (iReturn == SOCKET_ERROR) goto err_select;
	if (iReturn != 1 || !FD_ISSET(s, &wfds)) goto err_select_unexpected;

	WSASetLastError(NO_ERROR);
	SetLastError(NO_ERROR);
	return 0;

err_select_unexpected:
	FUNCIPCLOGW(L"select() returns unexpected value!");
	goto err_return;

err_select:
	dwLastError = GetLastError();
	iWSALastError = WSAGetLastError();
	FUNCIPCLOGW(L"select() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_timeout:
	FUNCIPCLOGW(L"select() timeout");
	iWSALastError = WSAETIMEDOUT;
	dwLastError = ERROR_TIMEOUT;
	goto err_return;

err_connect:
	dwLastError = GetLastError();
	iWSALastError = WSAGetLastError();
	FUNCIPCLOGW(L"connect() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_return:
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return SOCKET_ERROR;
}

int Ws2_32_LoopSend(void* pTempData, PXCH_UINT_PTR s, const char* SendBuf, int iLength)
{
	int iReturn;
	int iWSALastError;
	DWORD dwLastError;
	fd_set wfds;
	const char* pSendBuf = SendBuf;
	int iRemaining = iLength;

	while (iRemaining > 0) {
		FD_ZERO(&wfds);
		FD_SET(s, &wfds);
		iReturn = select(-1, NULL, &wfds, NULL, NULL);
		iWSALastError = WSAGetLastError();
		dwLastError = GetLastError();
		if (iReturn == SOCKET_ERROR) goto err_select;
		if (iReturn != 1 || !FD_ISSET(s, &wfds)) goto err_select_unexpected;

		iReturn = send(s, pSendBuf, iRemaining, 0);
		if (iReturn == SOCKET_ERROR) goto err_send;
		if (iReturn == 0) goto err_send_zerobytes;
		if (iReturn < iLength) {
			FUNCIPCLOGD(L"send() only sent %d/%d bytes", iReturn, iLength);
		}
		else if (iReturn == iLength) {
			FUNCIPCLOGV(L"send() sent %d/%d bytes", iReturn, iLength);
		}
		else goto err_send_unexpected;

		pSendBuf += iReturn;
		iRemaining -= iReturn;
	}

	SetLastError(NO_ERROR);
	WSASetLastError(NO_ERROR);
	return 0;

err_send_zerobytes:
	FUNCIPCLOGW(L"send() sends zero bytes!");
	goto err_return;

err_send_unexpected:
	FUNCIPCLOGW(L"send() occurs unexpected error!");
	goto err_return;

err_select_unexpected:
	FUNCIPCLOGW(L"select() returns unexpected value!");
	goto err_return;

err_send:
	dwLastError = GetLastError();
	iWSALastError = WSAGetLastError();
	FUNCIPCLOGW(L"send() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_select:
	dwLastError = GetLastError();
	iWSALastError = WSAGetLastError();
	FUNCIPCLOGW(L"select() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_return:
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return SOCKET_ERROR;
}

int Ws2_32_LoopRecv(void* pTempData, PXCH_UINT_PTR s, char* RecvBuf, int iLength)
{
	int iReturn;
	int iWSALastError;
	DWORD dwLastError;
	fd_set rfds;
	char* pRecvBuf = RecvBuf;
	int iRemaining = iLength;
	TIMEVAL Timeout = {
		.tv_sec = g_pPxchConfig->dwProxyConnectionTimeoutMillisecond / 1000,
		.tv_usec = g_pPxchConfig->dwProxyConnectionTimeoutMillisecond * 1000
	};

	while (iRemaining > 0) {
		FD_ZERO(&rfds);
		FD_SET(s, &rfds);
		iReturn = select(-1, &rfds, NULL, NULL, &Timeout);
		iWSALastError = WSAGetLastError();
		dwLastError = GetLastError();
		if (iReturn == 0) goto err_timeout;
		if (iReturn == SOCKET_ERROR) goto err_select;
		if (iReturn != 1 || !FD_ISSET(s, &rfds)) goto err_select_unexpected;

		iReturn = recv(s, pRecvBuf, iRemaining, 0);
		if (iReturn == SOCKET_ERROR) goto err_recv;
		if (iReturn == 0) goto err_recv_closed;
		if (iReturn < iLength) {
			FUNCIPCLOGD(L"recv() only received %d/%d bytes", iReturn, iLength);
		}
		else if (iReturn == iLength) {
			FUNCIPCLOGV(L"recv() received %d/%d bytes", iReturn, iLength);
		}
		else goto err_recv_unexpected;

		pRecvBuf += iReturn;
		iRemaining -= iReturn;
	}

	SetLastError(NO_ERROR);
	WSASetLastError(NO_ERROR);
	return 0;

err_recv_closed:
	FUNCIPCLOGW(L"recv() receives zero bytes, connection closed!");
	goto err_return;

err_recv_unexpected:
	FUNCIPCLOGW(L"recv() occurs unexpected error!");
	goto err_return;

err_select_unexpected:
	FUNCIPCLOGW(L"select() returns unexpected value!");
	goto err_return;

err_timeout:
	FUNCIPCLOGW(L"select() timeout");
	iWSALastError = WSAETIMEDOUT;
	dwLastError = ERROR_TIMEOUT;
	goto err_return;

err_recv:
	dwLastError = GetLastError();
	iWSALastError = WSAGetLastError();
	FUNCIPCLOGW(L"recv() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_select:
	dwLastError = GetLastError();
	iWSALastError = WSAGetLastError();
	FUNCIPCLOGW(L"select() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_return:
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return SOCKET_ERROR;
}

PXCH_DLL_API int Ws2_32_DirectConnect(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen)
{
	int iReturn;

	ODBGSTRLOGD(L"Ws2_32_DirectConnect 0 %p", pHostPort);
	if (HostIsType(INVALID, *pHostPort)) {
		FUNCIPCLOGW(L"Error connecting directly: address is invalid (%#06hx).", *(const PXCH_UINT16*)pHostPort);
		WSASetLastError(WSAEAFNOSUPPORT);
		return SOCKET_ERROR;
	}
	ODBGSTRLOGD(L"Ws2_32_DirectConnect 1");

	if (HostIsType(HOSTNAME, *pHostPort)) {
		PXCH_HOSTNAME_PORT* pHostnamePort = (PXCH_HOSTNAME_PORT*)pHostPort;
		ADDRINFOW AddrInfoHints = { 0 };
		ADDRINFOW* pAddrInfo;
		ADDRINFOW* pTempAddrInfo;
		PXCH_HOST_PORT NewHostPort = { 0 };

		// FUNCIPCLOGW(L"Warning connecting directly: address is hostname.");
		
		AddrInfoHints.ai_family = AF_UNSPEC;
		AddrInfoHints.ai_flags = 0;
		AddrInfoHints.ai_protocol = IPPROTO_TCP;
		AddrInfoHints.ai_socktype = SOCK_STREAM;

		if ((iReturn = orig_fpWs2_32_GetAddrInfoW(pHostnamePort->szValue, L"80", &AddrInfoHints, &pAddrInfo)) != 0 || pAddrInfo == NULL) {
			WSASetLastError(iReturn);
			return SOCKET_ERROR;
		}

		for (pTempAddrInfo = pAddrInfo; pTempAddrInfo; pTempAddrInfo = pTempAddrInfo->ai_next) {
			if (pTempAddrInfo->ai_family == ((const PXCH_TEMP_DATA*)pTempData)->CommonHeader.iOriginalAddrFamily) {
				break;
			}
		}

		if (pTempAddrInfo == NULL) {
			WSASetLastError(WSAEADDRNOTAVAIL);
			return SOCKET_ERROR;
		}

		CopyMemory(&NewHostPort, pTempAddrInfo->ai_addr, pTempAddrInfo->ai_addrlen);
		NewHostPort.CommonHeader.wPort = pHostPort->CommonHeader.wPort;
		pHostPort = &NewHostPort;
		iAddrLen = (int)pTempAddrInfo->ai_addrlen;
		FreeAddrInfoW(pAddrInfo);
	}

	FUNCIPCLOGD(L"Ws2_32_DirectConnect(%ls)", FormatHostPortToStr(pHostPort, iAddrLen));
	return Ws2_32_BlockConnect(pTempData, s, pHostPort, iAddrLen);
}

PXCH_DLL_API int Ws2_32_Socks5Connect(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen)
{
	const struct sockaddr_in* pSockAddrIpv4;
	const struct sockaddr_in6* pSockAddrIpv6;
	const PXCH_HOSTNAME_PORT* pAddrHostname;
	char* pszHostnameEnd;
	int iReturn;
	char SendBuf[PXCH_MAX_HOSTNAME_BUFSIZE + 10];
	char RecvBuf[PXCH_MAX_HOSTNAME_BUFSIZE + 10];
	char ServerBoundAddrType;
	int iWSALastError;
	DWORD dwLastError;

	if (!HostIsIp(*pHostPort) && !HostIsType(HOSTNAME, *pHostPort)) {
		FUNCIPCLOGW(L"Error connecting through Socks5: address is neither hostname nor ip.");
		WSASetLastError(WSAEAFNOSUPPORT);
		return SOCKET_ERROR;
	}

	FUNCIPCLOGD(L"Ws2_32_Socks5Connect(%ls)", FormatHostPortToStr(pHostPort, iAddrLen));

	if (HostIsType(IPV6, *pHostPort)) {
		pSockAddrIpv6 = (const struct sockaddr_in6*)pHostPort;

		// Connect
		CopyMemory(SendBuf, "\05\01\00\x04\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xEE\xEE", 22);
		CopyMemory(SendBuf + 4, &pSockAddrIpv6->sin6_addr, 16);
		CopyMemory(SendBuf + 4 + 16, &pSockAddrIpv6->sin6_port, 2);
		if ((iReturn = Ws2_32_LoopSend(pTempData, s, SendBuf, 22)) == SOCKET_ERROR) goto err_general;
	}
	else if (HostIsType(IPV4, *pHostPort)) {
		pSockAddrIpv4 = (const struct sockaddr_in*)pHostPort;

		// Connect
		CopyMemory(SendBuf, "\05\01\00\x01\xFF\xFF\xFF\xFF\xEE\xEE", 10);
		CopyMemory(SendBuf + 4, &pSockAddrIpv4->sin_addr, 4);
		CopyMemory(SendBuf + 8, &pSockAddrIpv4->sin_port, 2);
		if ((iReturn = Ws2_32_LoopSend(pTempData, s, SendBuf, 10)) == SOCKET_ERROR) goto err_general;
	} else if (HostIsType(HOSTNAME, *pHostPort)) {
		pAddrHostname = (const PXCH_HOSTNAME*)pHostPort;

		// Connect
		CopyMemory(SendBuf, "\05\01\00\x03", 4);
		StringCchPrintfExA(SendBuf + 5, PXCH_MAX_HOSTNAME_BUFSIZE, &pszHostnameEnd, NULL, 0, "%ls", pAddrHostname->szValue);
		*(unsigned char*)(SendBuf + 4) = (unsigned char)(pszHostnameEnd - (SendBuf + 5));
		CopyMemory(pszHostnameEnd, &pHostPort->HostnamePort.wPort, 2);
		if ((iReturn = Ws2_32_LoopSend(pTempData, s, SendBuf, (int)(pszHostnameEnd + 2 - SendBuf))) == SOCKET_ERROR) goto err_general;
	} else goto err_not_supported;

	if ((iReturn = Ws2_32_LoopRecv(pTempData, s, RecvBuf, 4)) == SOCKET_ERROR) goto err_general;
	if (RecvBuf[1] != '\00') goto err_data_invalid_2;
	ServerBoundAddrType = RecvBuf[3];
	if (ServerBoundAddrType == '\01') {
		// IPv4
		if ((iReturn = Ws2_32_LoopRecv(pTempData, s, RecvBuf, 4+2)) == SOCKET_ERROR) goto err_general;
	} else if (ServerBoundAddrType == '\03') {
		// Hostname
		if ((iReturn = Ws2_32_LoopRecv(pTempData, s, RecvBuf, 1)) == SOCKET_ERROR) goto err_general;
		if ((iReturn = Ws2_32_LoopRecv(pTempData, s, RecvBuf, ((unsigned char*)RecvBuf)[0] + 2)) == SOCKET_ERROR) goto err_general;
	} else if (ServerBoundAddrType == '\01') {
		// IPv6
		if ((iReturn = Ws2_32_LoopRecv(pTempData, s, RecvBuf, 16 + 2)) == SOCKET_ERROR) goto err_general;
	}

	SetLastError(NO_ERROR);
	WSASetLastError(NO_ERROR);
	return 0;

err_not_supported:
	FUNCIPCLOGW(L"Error connecting through Socks5: addresses not implemented.");
	iReturn = SOCKET_ERROR;
	dwLastError = ERROR_NOT_SUPPORTED;
	iWSALastError = WSAEAFNOSUPPORT;
	goto err_return;

err_data_invalid_2:
	FUNCIPCLOGW(L"Socks5 data format invalid: server disallows this connection");
	iReturn = SOCKET_ERROR;
	dwLastError = ERROR_ACCESS_DENIED;
	iWSALastError = WSAEACCES;
	goto err_return;

err_general:
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();
err_return:
	shutdown(s, SD_BOTH);
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iReturn;
}

PXCH_DLL_API int Ws2_32_Socks5Handshake(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */)
{
	int iReturn;
	char RecvBuf[256];
	int iWSALastError;
	DWORD dwLastError;
	BOOL bUsePassword;

	FUNCIPCLOGD(L"Ws2_32_Socks5Handshake()");

	bUsePassword = pProxy->Socks5.szUsername[0] && pProxy->Socks5.szPassword[0];

	if ((iReturn = Ws2_32_LoopSend(pTempData, s, bUsePassword ? "\05\01\02" : "\05\01\00", 3)) == SOCKET_ERROR) goto err_general;
	if ((iReturn = Ws2_32_LoopRecv(pTempData, s, RecvBuf, 2)) == SOCKET_ERROR) goto err_general;
	if ((!bUsePassword && RecvBuf[1] != '\00') || (bUsePassword && RecvBuf[1] != '\02')) goto err_data_invalid_1;

	if (bUsePassword) {
		size_t cbUsernameLength;
		size_t cbPasswordLength;
		unsigned char chUsernameLength;
		unsigned char chPasswordLength;
		char UserPassSendBuf[PXCH_MAX_USERNAME_BUFSIZE + PXCH_MAX_PASSWORD_BUFSIZE + 16];
		char *pUserPassSendBuf;

		StringCchLengthA(pProxy->Socks5.szUsername, _countof(pProxy->Socks5.szUsername), &cbUsernameLength);
		StringCchLengthA(pProxy->Socks5.szPassword, _countof(pProxy->Socks5.szPassword), &cbPasswordLength);
		chUsernameLength = (unsigned char)cbUsernameLength;
		chPasswordLength = (unsigned char)cbPasswordLength;

		pUserPassSendBuf = UserPassSendBuf;

		CopyMemory(pUserPassSendBuf, "\01", 1);
		pUserPassSendBuf += 1;
		CopyMemory(pUserPassSendBuf, &chUsernameLength, 1);
		pUserPassSendBuf += 1;
		CopyMemory(pUserPassSendBuf, pProxy->Socks5.szUsername, chUsernameLength);
		pUserPassSendBuf += chUsernameLength;
		CopyMemory(pUserPassSendBuf, &chPasswordLength, 1);
		pUserPassSendBuf += 1;
		CopyMemory(pUserPassSendBuf, pProxy->Socks5.szPassword, chPasswordLength);
		pUserPassSendBuf += chPasswordLength;

		if ((iReturn = Ws2_32_LoopSend(pTempData, s, UserPassSendBuf, (int)(pUserPassSendBuf - UserPassSendBuf))) == SOCKET_ERROR) goto err_general;
		if ((iReturn = Ws2_32_LoopRecv(pTempData, s, RecvBuf, 2)) == SOCKET_ERROR) goto err_general;
		if (RecvBuf[1] != '\00') goto err_data_invalid_2;
	}

	FUNCIPCLOGI(L"<> %ls", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));

	SetLastError(NO_ERROR);
	WSASetLastError(NO_ERROR);
	return 0;

err_data_invalid_1:
	FUNCIPCLOGW(L"Socks5 data format invalid: server disallows authentication method");
	dwLastError = ERROR_ACCESS_DENIED;
	iWSALastError = WSAEACCES;
	iReturn = SOCKET_ERROR;
	goto err_return;

err_data_invalid_2:
	FUNCIPCLOGW(L"Socks5 error: authentication failed");
	dwLastError = ERROR_ACCESS_DENIED;
	iWSALastError = WSAEACCES;
	iReturn = SOCKET_ERROR;
	goto err_return;

err_general:
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();
err_return:
	shutdown(s, SD_BOTH);
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iReturn;
}

int Ws2_32_GenericConnectTo(void* pTempData, PXCH_UINT_PTR s, PPXCH_CHAIN pChain, const PXCH_HOST_PORT* pHostPort, int iAddrLen)
{
	int iReturn;
	PXCH_CHAIN_NODE* pChainLastNode;
	PXCH_PROXY_DATA* pProxy;

	FUNCIPCLOGD(L"Ws2_32_GenericConnectTo(%ls)", FormatHostPortToStr(pHostPort, iAddrLen));

	if (*pChain == NULL) {
		SetProxyType(DIRECT, g_proxyDirect);
		// g_proxyDirect.Ws2_32_FpConnect = &Ws2_32_DirectConnect;
		// g_proxyDirect.Ws2_32_FpHandshake = NULL;
		StringCchCopyA(g_proxyDirect.Ws2_32_ConnectFunctionName, _countof(g_proxyDirect.Ws2_32_ConnectFunctionName), "Ws2_32_DirectConnect");
		StringCchCopyA(g_proxyDirect.Ws2_32_HandshakeFunctionName, _countof(g_proxyDirect.Ws2_32_HandshakeFunctionName), "");

		PXCH_CHAIN_NODE* pNewNodeDirect;

		pNewNodeDirect = HeapAlloc(GetProcessHeap(), 0, sizeof(PXCH_CHAIN_NODE));
		pNewNodeDirect->pProxy = (PXCH_PROXY_DATA*)&g_proxyDirect;
		pNewNodeDirect->prev = NULL;
		pNewNodeDirect->next = NULL;

		CDL_APPEND(*pChain, pNewNodeDirect);
	}

	pChainLastNode = (*pChain)->prev;	// Last
	pProxy = pChainLastNode->pProxy;

	iReturn = ((PXCH_WS2_32_FPCONNECT)GetProcAddress(GetModuleHandleW(g_szHookDllFileName), pProxy->CommonHeader.Ws2_32_ConnectFunctionName))(pTempData, s, pProxy, pHostPort, iAddrLen);
	return iReturn;
}

int Ws2_32_GenericTunnelTo(void* pTempData, PXCH_UINT_PTR s, PPXCH_CHAIN pChain, PXCH_PROXY_DATA* pProxy)
{
	DWORD dwLastError;
	int iWSALastError;
	int iReturn;
	PXCH_CHAIN_NODE* pNewNode;

	FUNCIPCLOGD(L"Ws2_32_GenericTunnelTo(%ls)", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));
	iReturn = Ws2_32_GenericConnectTo(pTempData, s, pChain, &pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen);
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();
	if (iReturn) goto err_connect;
	FUNCIPCLOGD(L"Ws2_32_GenericTunnelTo(%ls): after Ws2_32_GenericConnectTo()", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));

	pNewNode = HeapAlloc(GetProcessHeap(), 0, sizeof(PXCH_CHAIN_NODE));
	pNewNode->pProxy = pProxy;

	CDL_APPEND((*pChain), pNewNode);

	
	iReturn = ((PXCH_WS2_32_FPHANDSHAKE)GetProcAddress(GetModuleHandleW(g_szHookDllFileName), pProxy->CommonHeader.Ws2_32_HandshakeFunctionName))(pTempData, s, pProxy);
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();
	if (iReturn) goto err_handshake;
	FUNCIPCLOGD(L"Ws2_32_GenericTunnelTo(%ls): after pProxy->CommonHeader.Ws2_32_FpHandshake()", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));

	WSASetLastError(NO_ERROR);
	SetLastError(NO_ERROR);
	return iReturn;

err_connect:
	FUNCIPCLOGD(L"Ws2_32_GenericTunnelTo(%ls) connect failed!", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));
	goto err_return;
err_handshake:
	FUNCIPCLOGD(L"Ws2_32_GenericTunnelTo(%ls) handshake failed!", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));
err_return:
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iReturn;
}

// Hook connect

PROXY_FUNC2(Ws2_32, connect)
{
	int iReturn = 0;
	DWORD dwLastError = 0;
	int iWSALastError = 0;

	const PXCH_HOST_PORT* pHostPortForProxiedConnection = name;
	const PXCH_IP_PORT* pIpPortForDirectConnection = name;
	const PXCH_IP_PORT* pOriginalIpPort = name;
	int iOriginalAddrLen = namelen;
	PXCH_UINT32 dwTarget;

	PXCH_CHAIN Chain = NULL;
	PXCH_WS2_32_TEMP_DATA TempData;

	PXCH_HOSTNAME_PORT ReverseLookedupHostnamePort = { 0 };
	PXCH_IP_PORT ReverseLookedupResolvedIpPort = { 0 };

	DWORD dw;

	RestoreChildDataIfNecessary();

	FUNCIPCLOGD(L"Ws2_32.dll connect(%d, %ls, %d) called", s, FormatHostPortToStr(name, namelen), namelen);

	TempData.iOriginalAddrFamily = ((struct sockaddr*)pOriginalIpPort)->sa_family;

	switch (ReverseLookupForHost(&ReverseLookedupHostnamePort, &ReverseLookedupResolvedIpPort, &pIpPortForDirectConnection, &pHostPortForProxiedConnection, &dwTarget, pOriginalIpPort, iOriginalAddrLen)) {
	case NO_ERROR:
		break;
	case ERROR_NOT_SUPPORTED:
		goto addr_not_supported_end;
	default:
		goto not_wsa_error_end;
	}

	if (dwTarget == PXCH_RULE_TARGET_DIRECT) {
		iReturn = Ws2_32_OriginalConnect(&TempData, s, pIpPortForDirectConnection, namelen);
		goto success_revert_connect_errcode_end;
	}

	if (dwTarget == PXCH_RULE_TARGET_BLOCK) {
		goto block_end;
	}

	for (dw = 0; dw < g_pPxchConfig->dwProxyNum; dw++) {
		if ((iReturn = Ws2_32_GenericTunnelTo(&TempData, s, &Chain, &PXCH_CONFIG_PROXY_ARR(g_pPxchConfig)[dw])) == SOCKET_ERROR) goto record_error_end;
	}
	if ((iReturn = Ws2_32_GenericConnectTo(&TempData, s, &Chain, pHostPortForProxiedConnection, namelen)) == SOCKET_ERROR) goto record_error_end;

success_revert_connect_errcode_end:
	iWSALastError = TempData.iConnectWSALastError;
	dwLastError = TempData.iConnectLastError;
	iReturn = TempData.iConnectReturn;
	goto end;

addr_not_supported_end:
	iWSALastError = WSAEAFNOSUPPORT;
	dwLastError = ERROR_NOT_SUPPORTED;
	iReturn = SOCKET_ERROR;
	goto end;

block_end:
	iWSALastError = WSAECONNREFUSED;
	dwLastError = ERROR_REQUEST_REFUSED;
	iReturn = SOCKET_ERROR;
	goto end;

record_error_end:
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();
	goto end;

not_wsa_error_end:
	iWSALastError = WSABASEERR;
	goto end;

end:
	PrintConnectResultAndFreeResources(L"Ws2_32.dll connect", s, pOriginalIpPort, iOriginalAddrLen, pIpPortForDirectConnection, pHostPortForProxiedConnection, dwTarget, &Chain, iReturn, iReturn == 0, iWSALastError);
	
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iReturn;
}


// Hook ConnectEx

Mswsock_ConnectEx_SIGN_WITH_PTEMPDATA(Mswsock_OriginalConnectEx)
{
	BOOL bReturn;
	int iWSALastError;
	DWORD dwLastError;
	PXCH_MSWSOCK_TEMP_DATA* pMswsock_TempData = pTempData;

	pMswsock_TempData->bConnectReturn = bReturn = orig_fpMswsock_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
	pMswsock_TempData->iConnectWSALastError = iWSALastError = WSAGetLastError();
	pMswsock_TempData->iConnectLastError = dwLastError = GetLastError();

	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return bReturn;
}

PROXY_FUNC2(Mswsock, ConnectEx)
{
	int iReturn;
	BOOL bReturn;
	DWORD dwLastError = 0;
	int iWSALastError = 0;

	const PXCH_HOST_PORT* pHostPortForProxiedConnection = name;
	const PXCH_IP_PORT* pIpPortForDirectConnection = name;
	const PXCH_IP_PORT* pOriginalIpPort = name;
	int iOriginalAddrLen = namelen;
	PXCH_UINT32 dwTarget;

	PXCH_CHAIN Chain = NULL;
	PXCH_MSWSOCK_TEMP_DATA TempData;

	PXCH_HOSTNAME_PORT ReverseLookedupHostnamePort = { 0 };
	PXCH_IP_PORT ReverseLookedupResolvedIpPort = { 0 };

	DWORD dw;

	RestoreChildDataIfNecessary();

	FUNCIPCLOGD(L"Mswsock.dll (FP)ConnectEx(%d, %ls, %d) called", s, FormatHostPortToStr(name, namelen), namelen);

	TempData.iOriginalAddrFamily = ((struct sockaddr*)pOriginalIpPort)->sa_family;

	switch (ReverseLookupForHost(&ReverseLookedupHostnamePort, &ReverseLookedupResolvedIpPort, &pIpPortForDirectConnection, &pHostPortForProxiedConnection, &dwTarget, pOriginalIpPort, iOriginalAddrLen)) {
	case NO_ERROR:
		break;
	case ERROR_NOT_SUPPORTED:
		goto addr_not_supported_end;
	default:
		goto not_wsa_error_end;
	}

	if (dwTarget == PXCH_RULE_TARGET_DIRECT) {
		bReturn = Mswsock_OriginalConnectEx(&TempData, s, pIpPortForDirectConnection, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
		goto success_set_errcode_zero_end;
	}

	if (dwTarget == PXCH_RULE_TARGET_BLOCK) {
		goto block_end;
	}

	for (dw = 0; dw < g_pPxchConfig->dwProxyNum; dw++) {
		if ((iReturn = Ws2_32_GenericTunnelTo(&TempData, s, &Chain, &PXCH_CONFIG_PROXY_ARR(g_pPxchConfig)[dw])) == SOCKET_ERROR) goto record_error_end;
	}
	if ((iReturn = Ws2_32_GenericConnectTo(&TempData, s, &Chain, pHostPortForProxiedConnection, namelen)) == SOCKET_ERROR) goto record_error_end;

success_set_errcode_zero_end:
	iWSALastError = NO_ERROR;
	dwLastError = NO_ERROR;
	bReturn = TRUE;
	goto end;

addr_not_supported_end:
	iWSALastError = WSAEAFNOSUPPORT;
	dwLastError = ERROR_NOT_SUPPORTED;
	bReturn = FALSE;
	goto end;

block_end:
	iWSALastError = WSAECONNREFUSED;
	dwLastError = ERROR_REQUEST_REFUSED;
	bReturn = FALSE;
	goto end;

record_error_end:
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();
	bReturn = FALSE;
	goto end;

not_wsa_error_end:
	iWSALastError = WSABASEERR;
	bReturn = FALSE;
	goto end;

end:
	PrintConnectResultAndFreeResources(L"Mswsock.dll (FP)ConnectEx", s, pOriginalIpPort, iOriginalAddrLen, pIpPortForDirectConnection, pHostPortForProxiedConnection, dwTarget, &Chain, (int)bReturn, bReturn, iWSALastError);

	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return bReturn;
}

// Hook WSAStartup

PROXY_FUNC2(Ws2_32, WSAStartup)
{
	// Not used
	return 0;
}

// Hook WSAConnect

Ws2_32_WSAConnect_SIGN_WITH_PTEMPDATA(Ws2_32_OriginalWSAConnect)
{
	int iReturn;
	int iWSALastError = 0;
	DWORD dwLastError = 0;
	PXCH_WS2_32_TEMP_DATA* pWs2_32_TempData = pTempData;

	pWs2_32_TempData->iConnectReturn = iReturn = orig_fpWs2_32_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
	pWs2_32_TempData->iConnectWSALastError = iWSALastError = WSAGetLastError();
	pWs2_32_TempData->iConnectLastError = dwLastError = GetLastError();

	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iReturn;
}

PROXY_FUNC2(Ws2_32, WSAConnect)
{
	int iReturn = 0;
	DWORD dwLastError = 0;
	int iWSALastError = 0;

	const PXCH_HOST_PORT* pHostPortForProxiedConnection = name;
	const PXCH_IP_PORT* pIpPortForDirectConnection = name;
	const PXCH_IP_PORT* pOriginalIpPort = name;
	int iOriginalAddrLen = namelen;
	PXCH_UINT32 dwTarget;

	PXCH_CHAIN Chain = NULL;
	PXCH_WS2_32_TEMP_DATA TempData;

	PXCH_HOSTNAME_PORT ReverseLookedupHostnamePort = { 0 };
	PXCH_IP_PORT ReverseLookedupResolvedIpPort = { 0 };

	DWORD dw;

	RestoreChildDataIfNecessary();

	FUNCIPCLOGD(L"Ws2_32.dll WSAConnect(%d, %ls, %d) called", s, FormatHostPortToStr(name, namelen), namelen);

	TempData.iOriginalAddrFamily = ((struct sockaddr*)pOriginalIpPort)->sa_family;

	if (lpCallerData != NULL || lpCalleeData != NULL) {
		FUNCIPCLOGD(L"Ws2_32.dll WSAConnect(): lpCallerData or lpCalleeData not NULL, forcing DIRECT");
		dwTarget = PXCH_RULE_TARGET_DIRECT;
	} else {

		switch (ReverseLookupForHost(&ReverseLookedupHostnamePort, &ReverseLookedupResolvedIpPort, &pIpPortForDirectConnection, &pHostPortForProxiedConnection, &dwTarget, pOriginalIpPort, iOriginalAddrLen)) {
		case NO_ERROR:
			break;
		case ERROR_NOT_SUPPORTED:
			goto addr_not_supported_end;
		default:
			goto not_wsa_error_end;
		}

	}

	if (dwTarget == PXCH_RULE_TARGET_DIRECT) {
		iReturn = Ws2_32_OriginalWSAConnect(&TempData, s, pIpPortForDirectConnection, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
		goto success_revert_connect_errcode_end;
	}

	if (dwTarget == PXCH_RULE_TARGET_BLOCK) {
		goto block_end;
	}

	for (dw = 0; dw < g_pPxchConfig->dwProxyNum; dw++) {
		if ((iReturn = Ws2_32_GenericTunnelTo(&TempData, s, &Chain, &PXCH_CONFIG_PROXY_ARR(g_pPxchConfig)[dw])) == SOCKET_ERROR) goto record_error_end;
	}
	if ((iReturn = Ws2_32_GenericConnectTo(&TempData, s, &Chain, pHostPortForProxiedConnection, namelen)) == SOCKET_ERROR) goto record_error_end;

success_revert_connect_errcode_end:
	iWSALastError = TempData.iConnectWSALastError;
	dwLastError = TempData.iConnectLastError;
	iReturn = TempData.iConnectReturn;
	goto end;

addr_not_supported_end:
	iWSALastError = WSAEAFNOSUPPORT;
	dwLastError = ERROR_NOT_SUPPORTED;
	iReturn = SOCKET_ERROR;
	goto end;

block_end:
	iWSALastError = WSAECONNREFUSED;
	dwLastError = ERROR_REQUEST_REFUSED;
	iReturn = SOCKET_ERROR;
	goto end;

record_error_end:
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();
	goto end;

not_wsa_error_end:
	iWSALastError = WSABASEERR;
	goto end;

end:
	PrintConnectResultAndFreeResources(L"Ws2_32.dll connect", s, pOriginalIpPort, iOriginalAddrLen, pIpPortForDirectConnection, pHostPortForProxiedConnection, dwTarget, &Chain, iReturn, iReturn == 0, iWSALastError);
	
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iReturn;
}

// Hook gethostbyname

PROXY_FUNC2(Ws2_32, gethostbyname)
{
	struct hostent* pResolvedHostent = NULL;
	struct hostent* pReturnHostent = NULL;
	struct hostent* pNewHostentResult = NULL;
	int iWSALastError = 0;
	DWORD dwLastError = 0;
	DWORD dw;

	ADDRINFOW RequeryAddrInfoHints;
	ADDRINFOW* pRequeryAddrInfo = NULL;
	PXCH_HOSTNAME OriginalHostname;
	PXCH_HOSTNAME ResolvedHostname;
	PXCH_IP_PORT IpPortResolvedByHosts;
	PXCH_UINT32 dwIpNum = 0;
	PXCH_IP_ADDRESS Ips[PXCH_MAX_ARRAY_IP_NUM];
	PXCH_UINT32 dwTarget;
	BOOL bHasMatchedHostnameRule;

	PXCH_IPC_MSGBUF chMessageBuf;
	PXCH_UINT32 cbMessageSize;
	PXCH_IPC_MSGBUF chRespMessageBuf;
	PXCH_UINT32 cbRespMessageSize;
	PXCH_IP_ADDRESS FakeIps[2];
	PXCH_IP_ADDRESS* pFakeIps;

	BOOL bShouldReturnResolvedResult = FALSE;
	BOOL bShouldUseResolvedResult = FALSE;
	BOOL bShouldUseHostsResult = FALSE;
	BOOL bShouldReturnHostsResult = FALSE;
	BOOL bShouldReturnFakeIp = FALSE;

	// Print DNS query
	FUNCIPCLOGD(L"Ws2_32.dll gethostbyname(" WPRS L") called", name);

	ZeroMemory(&IpPortResolvedByHosts, sizeof(IpPortResolvedByHosts));
	ZeroMemory(&RequeryAddrInfoHints, sizeof(RequeryAddrInfoHints));
	RequeryAddrInfoHints.ai_family = AF_UNSPEC;
	RequeryAddrInfoHints.ai_flags = AI_NUMERICHOST;
	RequeryAddrInfoHints.ai_socktype = SOCK_STREAM;
	RequeryAddrInfoHints.ai_protocol = IPPROTO_TCP;

	ZeroMemory(&OriginalHostname, sizeof(PXCH_HOSTNAME));
	OriginalHostname.wPort = 0;
	OriginalHostname.wTag = PXCH_HOST_TYPE_HOSTNAME;
	StringCchPrintfW(OriginalHostname.szValue, _countof(OriginalHostname.szValue), L"%S", name);

	// Decide if we should use hosts entry
	if (g_pPxchConfig->dwWillResolveLocallyIfMatchHosts && ResolveByHostsFile((PXCH_IP_ADDRESS*)&IpPortResolvedByHosts, &OriginalHostname, AF_INET)) {
		bShouldReturnHostsResult = TRUE;
		bShouldUseHostsResult = TRUE;
	}

	// Decide if we should use original result
	if (!bShouldReturnHostsResult && !g_pPxchConfig->dwWillUseFakeIpAsRemoteDns) {
		bShouldReturnResolvedResult = TRUE;
		bShouldUseResolvedResult = TRUE;
	} else if (!bShouldReturnHostsResult) {
		ZeroMemory(&RequeryAddrInfoHints, sizeof(RequeryAddrInfoHints));
		RequeryAddrInfoHints.ai_family = AF_UNSPEC;
		RequeryAddrInfoHints.ai_flags = AI_NUMERICHOST;
		RequeryAddrInfoHints.ai_socktype = SOCK_STREAM;
		RequeryAddrInfoHints.ai_protocol = IPPROTO_TCP;

		if (name == NULL
			|| name[0] == '\0'
			|| orig_fpWs2_32_GetAddrInfoW(OriginalHostname.szValue, L"80", &RequeryAddrInfoHints, &pRequeryAddrInfo) != WSAHOST_NOT_FOUND
		) {
			FUNCIPCLOGD(L"conditons not satisfied; not hijacking name query");
			bShouldReturnResolvedResult = TRUE;
			bShouldUseResolvedResult = TRUE;
		}
	}

	if (pRequeryAddrInfo) {
		orig_fpWs2_32_FreeAddrInfoW(pRequeryAddrInfo);
		pRequeryAddrInfo = NULL;
	}

	if (!bShouldReturnHostsResult && !bShouldReturnResolvedResult) {
		// Won't match port!
		dwTarget = GetTargetByRule(&bHasMatchedHostnameRule, NULL, NULL, NULL, (PXCH_HOST_PORT*)&OriginalHostname);
		bShouldReturnFakeIp = bHasMatchedHostnameRule || g_pPxchConfig->dwWillUseFakeIpWhenHostnameNotMatched;
		bShouldReturnResolvedResult = !bShouldReturnFakeIp;
		if (dwTarget == PXCH_RULE_TARGET_DIRECT) {
			bShouldUseResolvedResult = TRUE;
		}
	}

	if (bShouldReturnResolvedResult) {
		bShouldUseResolvedResult = TRUE;
	}

	if (bShouldUseResolvedResult) {
		if (!g_pPxchConfig->dwWillResolveLocallyIfMatchHosts && ResolveByHostsFile((PXCH_IP_ADDRESS*)&IpPortResolvedByHosts, &OriginalHostname, AF_INET)) {
			bShouldUseHostsResult = TRUE;
		}
	}

	if (bShouldUseResolvedResult && !bShouldUseHostsResult) {
		pResolvedHostent = NULL;
		pResolvedHostent = orig_fpWs2_32_gethostbyname(name);
		iWSALastError = WSAGetLastError();
	    dwLastError = GetLastError();

		if (pResolvedHostent == NULL
			|| pResolvedHostent->h_length != sizeof(PXCH_UINT32)
		) {
			bShouldReturnFakeIp = FALSE;
			bShouldReturnResolvedResult = TRUE;
		}

		HostentToHostnameAndIps(&ResolvedHostname, &dwIpNum, Ips, pResolvedHostent);
		if (dwIpNum == 0) {
			bShouldReturnFakeIp = FALSE;
			bShouldReturnResolvedResult = TRUE;
		}
	}

	if (bShouldUseHostsResult) {
		pResolvedHostent = NULL;

		HostnameAndIpsToHostent(
			&pResolvedHostent,
			(g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? TlsGetValue(g_dwTlsIndex) : pHostentPseudoTls,
			&OriginalHostname,
			1,
			&IpPortResolvedByHosts
		);

		iWSALastError = NO_ERROR;
		dwLastError = NO_ERROR;
	}

	if (bShouldReturnFakeIp) {
		int iIpFamilyAllowed;

		BOOL bShouldReturnIpv4 = FALSE;
		BOOL bShouldReturnIpv6 = FALSE;

		if (bShouldUseResolvedResult) {
			// We should not return fake IPs with types that are not in resolved IPs, because we know later we will connect to one of the resolved IPs
			for (dw = 0; dw < dwIpNum; dw++) {
				if (Ips[dw].CommonHeader.wTag == PXCH_HOST_TYPE_IPV4) {
					bShouldReturnIpv4 = TRUE;
				}
				if (Ips[dw].CommonHeader.wTag == PXCH_HOST_TYPE_IPV6) {
					bShouldReturnIpv6 = TRUE;
				}
			}
		} else {
			// We can always return fake IPv4 address, because locally resolved IPs are not used
			// Note that gethostbyname() can only return IPv4 address at most
			bShouldReturnIpv4 = TRUE;
			bShouldReturnIpv6 = FALSE;
		}

		if ((dwLastError = HostnameAndIpsToMessage(chMessageBuf, &cbMessageSize, GetCurrentProcessId(), &OriginalHostname, g_pPxchConfig->dwWillMapResolvedIpToHost, dwIpNum, Ips, dwTarget)) != NO_ERROR) goto err;

		if ((dwLastError = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, &cbRespMessageSize)) != NO_ERROR) goto err;

		if ((dwLastError = MessageToHostnameAndIps(NULL, NULL, NULL, NULL /*Must be 2*/, FakeIps, NULL, chRespMessageBuf, cbRespMessageSize)) != NO_ERROR) goto err;

		iIpFamilyAllowed = 0;
		pFakeIps = FakeIps + 1;

		if (g_pPxchConfig->dwWillFirstTunnelUseIpv4 && bShouldReturnIpv4) {
			iIpFamilyAllowed++;
			pFakeIps--;
		}
		if (g_pPxchConfig->dwWillFirstTunnelUseIpv6 && bShouldReturnIpv6) {
			iIpFamilyAllowed++;
		}
		HostnameAndIpsToHostent(&pNewHostentResult, (g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? TlsGetValue(g_dwTlsIndex) : pHostentPseudoTls, &OriginalHostname, iIpFamilyAllowed, pFakeIps);
		iWSALastError = NO_ERROR;
		dwLastError = NO_ERROR;

		pReturnHostent = pNewHostentResult;
	}

	if (bShouldReturnResolvedResult) {
		pReturnHostent = pResolvedHostent;
	}

	if (bShouldReturnHostsResult) {
		pReturnHostent = pResolvedHostent;
		iWSALastError = NO_ERROR;
		dwLastError = NO_ERROR;
	}

	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return pReturnHostent;

err:
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return NULL;
}

// Hook gethostbyaddr

PROXY_FUNC2(Ws2_32, gethostbyaddr)
{
	FUNCIPCLOGD(L"Ws2_32.dll gethostbyaddr() called");

	return orig_fpWs2_32_gethostbyaddr(addr, len, type);
}

// Hook getaddrinfo

PROXY_FUNC2(Ws2_32, getaddrinfo)
{
	const ADDRINFOA* pHintsCast = pHints;
	const ADDRINFOW* pHintsCastW = pHints;
	
	PADDRINFOW pResultCastW;
	PXCH_ADDRINFOA* pTempPxchAddrInfoA;
	PADDRINFOA pTempAddrInfoA;
	PADDRINFOW pTempAddrInfoW;
	PXCH_ADDRINFOA* arrPxchAddrInfoA = NULL;
	PADDRINFOA* ppResultCastA = ppResult;
	PADDRINFOA* ppTempAddrInfoA;

	int iReturn;
	DWORD dwLastError;
	int iWSALastError;

	WCHAR* pszAddrsBuf;
	PADDRINFOA pResultCast;

	DWORD dwAddrInfoLen;
	DWORD dw;

	WCHAR szAddrsBuf[200];
	WCHAR pNodeNameW[PXCH_MAX_HOSTNAME_BUFSIZE];
	WCHAR pServiceNameW[PXCH_MAX_HOSTNAME_BUFSIZE];

	(void)pHintsCast;
	FUNCIPCLOGD(L"Ws2_32.dll getaddrinfo(%S, %S, AF%#010x, FL%#010x, ST%#010x, PT%#010x) called", pNodeName, pServiceName, pHintsCast ? pHintsCast->ai_family : -1, pHintsCast ? pHintsCast->ai_flags : -1, pHintsCast ? pHintsCast->ai_socktype : -1, pHintsCast ? pHintsCast->ai_protocol : -1);

	if (pNodeName) StringCchPrintfW(pNodeNameW, _countof(pNodeNameW), L"%S", pNodeName);
	if (pServiceName) StringCchPrintfW(pServiceNameW, _countof(pServiceNameW), L"%S", pServiceName);

	//iReturn = ProxyWs2_32_GetAddrInfoW(pNodeNameW, pServiceNameW, pHintsCastW, &pResultCastW);
	iReturn = ProxyWs2_32_GetAddrInfoW(pNodeName ? pNodeNameW : NULL, pServiceName ? pServiceNameW : NULL, pHintsCastW, &pResultCastW);
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();
	FUNCIPCLOGD(L"Ws2_32.dll getaddrinfo(%S, %S, AF%#010x, FL%#010x, ST%#010x, PT%#010x): ProxyWs2_32_GetAddrInfoW ret: %d", pNodeName, pServiceName, pHintsCast ? pHintsCast->ai_family : -1, pHintsCast ? pHintsCast->ai_flags : -1, pHintsCast ? pHintsCast->ai_socktype : -1, pHintsCast ? pHintsCast->ai_protocol : -1, iReturn);

	HeapLock(GetProcessHeap());
	
	for (dwAddrInfoLen = 0, pTempAddrInfoW = pResultCastW; pTempAddrInfoW; pTempAddrInfoW = pTempAddrInfoW->ai_next, dwAddrInfoLen++)
		;

	if (dwAddrInfoLen) {
		arrPxchAddrInfoA = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PXCH_ADDRINFOA) * dwAddrInfoLen);
		utarray_push_back(g_arrHeapAllocatedPointers, &arrPxchAddrInfoA);
	}

	HeapUnlock(GetProcessHeap());

	ppTempAddrInfoA = ppResultCastA;
	*ppResultCastA = NULL;

	for (dw = 0, pTempAddrInfoW = pResultCastW; dw < dwAddrInfoLen; pTempAddrInfoW = pTempAddrInfoW->ai_next, dw++) {
		*ppTempAddrInfoA = (ADDRINFOA*)&arrPxchAddrInfoA[dw];
		pTempAddrInfoA = *ppTempAddrInfoA;
		pTempPxchAddrInfoA = (PXCH_ADDRINFOA*)*ppTempAddrInfoA;

		CopyMemory(&pTempPxchAddrInfoA->IpPort, pTempAddrInfoW->ai_addr, pTempAddrInfoW->ai_addrlen);
		StringCchPrintfA(pTempPxchAddrInfoA->HostnameBuf, _countof(pTempPxchAddrInfoA->HostnameBuf), "%ls", pTempAddrInfoW->ai_canonname ? pTempAddrInfoW->ai_canonname : L"");

		pTempAddrInfoA->ai_addr = (struct sockaddr*)&pTempPxchAddrInfoA->IpPort;
		pTempAddrInfoA->ai_addrlen = pTempAddrInfoW->ai_addrlen;
		pTempAddrInfoA->ai_canonname = (pTempAddrInfoW->ai_canonname ? pTempPxchAddrInfoA->HostnameBuf : NULL);
		pTempAddrInfoA->ai_family = pTempAddrInfoW->ai_family;
		pTempAddrInfoA->ai_flags = pTempAddrInfoW->ai_flags;
		pTempAddrInfoA->ai_protocol = pTempAddrInfoW->ai_protocol;
		pTempAddrInfoA->ai_socktype = pTempAddrInfoW->ai_socktype;
		pTempAddrInfoA->ai_next = NULL;

		ppTempAddrInfoA = &pTempAddrInfoA->ai_next;
	}

	ProxyWs2_32_FreeAddrInfoW(pResultCastW);

	szAddrsBuf[0] = L'\0';
	pszAddrsBuf = szAddrsBuf;

	for (pResultCast = (*ppResultCastA); pResultCast; pResultCast = pResultCast->ai_next) {
		StringCchPrintfExW(pszAddrsBuf, _countof(szAddrsBuf) - (pszAddrsBuf - szAddrsBuf), &pszAddrsBuf, NULL, 0, L"%ls%ls", pResultCast == (*ppResultCastA) ? L"" : L", ", FormatHostPortToStr(pResultCast->ai_addr, (int)pResultCast->ai_addrlen));
	}

	FUNCIPCLOGD(L"Ws2_32.dll getaddrinfo(" WPRS L", " WPRS L", ...) result: %ls", pNodeName, pServiceName, szAddrsBuf);

	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iReturn;
}

// Hook GetAddrInfoW

PROXY_FUNC2(Ws2_32, GetAddrInfoW)
{
	const ADDRINFOW* pHintsCast;
	PADDRINFOW* ppResultCast = ppResult;
	PADDRINFOW pResolvedResultCast = NULL;
	int iReturn;
	DWORD dwLastError;
	int iWSALastError;
	DWORD dw;

	WCHAR* pszAddrsBuf;
	PADDRINFOW pResultCast;

	PXCH_UINT32 dwTarget;
	BOOL bHasMatchedHostnameRule;

	ADDRINFOW* pQueryPortAddrInfo = NULL;
	ADDRINFOW* pRequeryAddrInfo = NULL;

	ADDRINFOW DefaultHints;
	WCHAR szAddrsBuf[1024];
	PXCH_IP_PORT IpPortResolvedByHosts;
	PXCH_HOST_PORT HostPort;
	PXCH_HOSTNAME Hostname;
	ADDRINFOW RequeryAddrInfoHints;

	BOOL bShouldReturnResolvedResult = FALSE;
	BOOL bShouldUseResolvedResult = FALSE;
	BOOL bShouldUseHostsResult = FALSE;
	BOOL bShouldReturnHostsResult = FALSE;
	BOOL bShouldReturnFakeIp = FALSE;
	PXCH_IPC_MSGBUF chMessageBuf;
	PXCH_IPC_MSGBUF chRespMessageBuf;
	PXCH_IP_ADDRESS Ips[PXCH_MAX_ARRAY_IP_NUM];
	PXCH_IP_PORT FakeIpPorts[2];

	pHintsCast = pHints ? pHints : &DefaultHints;

	ZeroMemory(&IpPortResolvedByHosts, sizeof(IpPortResolvedByHosts));
	ZeroMemory(&DefaultHints, sizeof(DefaultHints));
	// To distinguish case when pHints == NULL when printing
	DefaultHints.ai_family = -1;
	DefaultHints.ai_flags = -1;
	DefaultHints.ai_socktype = -1;
	DefaultHints.ai_protocol = -1;

	// Print DNS query
	FUNCIPCLOGD(L"Ws2_32.dll GetAddrInfoW(%ls, %ls, AF%#010x, FL%#010x, ST%#010x, PT%#010x) called", pNodeName, pServiceName, pHintsCast->ai_family, pHintsCast->ai_flags, pHintsCast->ai_socktype, pHintsCast->ai_protocol);

	DefaultHints.ai_family = AF_UNSPEC;
	DefaultHints.ai_flags = 0;
	DefaultHints.ai_socktype = SOCK_STREAM;
	DefaultHints.ai_protocol = IPPROTO_TCP;

	iReturn = orig_fpWs2_32_GetAddrInfoW(L"127.0.0.1", pServiceName, NULL, &pQueryPortAddrInfo);
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();
	// Most probably WSATYPE_NOT_FOUND
	if (iReturn != NO_ERROR || pQueryPortAddrInfo == NULL) goto err;

	ZeroMemory(&HostPort, sizeof(PXCH_HOST_PORT));
	SetHostType(HOSTNAME, HostPort);
	HostPort.HostnamePort.wPort = ((PXCH_IP_PORT*)pQueryPortAddrInfo->ai_addr)->CommonHeader.wPort;
	if (pQueryPortAddrInfo) {
		orig_fpWs2_32_FreeAddrInfoW(pQueryPortAddrInfo);
		pQueryPortAddrInfo = NULL;
	}
	StringCchCopyW(HostPort.HostnamePort.szValue, _countof(HostPort.HostnamePort.szValue), pNodeName);

	Hostname = HostPort.HostnamePort;
	Hostname.wPort = 0;

	// Decide if we should use hosts entry
	if (g_pPxchConfig->dwWillResolveLocallyIfMatchHosts && ResolveByHostsFile((PXCH_IP_ADDRESS*)&IpPortResolvedByHosts, &Hostname, pHintsCast->ai_family)) {
		bShouldReturnHostsResult = TRUE;
		bShouldUseHostsResult = TRUE;
	}

	// Decide if we should use original result
	if (!bShouldReturnHostsResult && !g_pPxchConfig->dwWillUseFakeIpAsRemoteDns) {
		bShouldReturnResolvedResult = TRUE;
		bShouldUseResolvedResult = TRUE;
	} else if (!bShouldReturnHostsResult) {
		ZeroMemory(&RequeryAddrInfoHints, sizeof(RequeryAddrInfoHints));
		RequeryAddrInfoHints.ai_family = AF_UNSPEC;
		RequeryAddrInfoHints.ai_protocol = pHintsCast->ai_protocol;
		RequeryAddrInfoHints.ai_socktype = pHintsCast->ai_socktype;
		RequeryAddrInfoHints.ai_flags = AI_NUMERICHOST;

		// See if we should hijack this query(it needs to satisfy several conditions)
		if (!(
			pNodeName != NULL
			&& pNodeName[0] != L'\0'
			&& (
				pHintsCast->ai_family == AF_UNSPEC
				|| pHintsCast->ai_family == AF_INET
				|| pHintsCast->ai_family == AF_INET6)
			&& (pHintsCast->ai_protocol == IPPROTO_TCP
				|| pHintsCast->ai_protocol == IPPROTO_UDP
				|| pHintsCast->ai_protocol == 0)
			&& (pHintsCast->ai_socktype == SOCK_STREAM
				|| pHintsCast->ai_socktype == SOCK_DGRAM
				|| pHintsCast->ai_socktype == 0)
			&& ((pHintsCast->ai_flags & (AI_PASSIVE | AI_NUMERICHOST)) == 0)
			&& orig_fpWs2_32_GetAddrInfoW(pNodeName, pServiceName, &RequeryAddrInfoHints, &pRequeryAddrInfo) == WSAHOST_NOT_FOUND
		)) {
			FUNCIPCLOGD(L"conditons not satisfied; not hijacking name query");
			bShouldReturnResolvedResult = TRUE;
			bShouldUseResolvedResult = TRUE;
		}
	}

	if (pRequeryAddrInfo) {
		orig_fpWs2_32_FreeAddrInfoW(pRequeryAddrInfo);
		pRequeryAddrInfo = NULL;
	}

	if (!bShouldReturnHostsResult && !bShouldReturnResolvedResult) {
		dwTarget = GetTargetByRule(&bHasMatchedHostnameRule, NULL, NULL, NULL, &HostPort);
		bShouldReturnFakeIp = bHasMatchedHostnameRule || g_pPxchConfig->dwWillUseFakeIpWhenHostnameNotMatched;
		bShouldReturnResolvedResult = !bShouldReturnFakeIp;

		if (dwTarget == PXCH_RULE_TARGET_DIRECT) {
			bShouldUseResolvedResult = TRUE;
		}
	}

	if (bShouldReturnResolvedResult) {
		bShouldUseResolvedResult = TRUE;
	}

	if (bShouldUseResolvedResult) {
		if (!g_pPxchConfig->dwWillResolveLocallyIfMatchHosts && ResolveByHostsFile((PXCH_IP_ADDRESS*)&IpPortResolvedByHosts, &Hostname, pHintsCast->ai_family)) {
			bShouldUseHostsResult = TRUE;
		}
	}

	if (bShouldUseResolvedResult && !bShouldUseHostsResult) {
		pResolvedResultCast = NULL;
		
		iReturn = orig_fpWs2_32_GetAddrInfoW(pNodeName, pServiceName, pHints, &pResolvedResultCast);
		iWSALastError = WSAGetLastError();
		dwLastError = GetLastError();

		FUNCIPCLOGD(L"Ws2_32.dll GetAddrInfoW(%ls, %ls, AF%#010x, FL%#010x, ST%#010x, PT%#010x): orig_fpWs2_32_GetAddrInfoW ret: %d", pNodeName, pServiceName, pHintsCast->ai_family, pHintsCast->ai_flags, pHintsCast->ai_socktype, pHintsCast->ai_protocol, iReturn);

		szAddrsBuf[0] = L'\0';
		pszAddrsBuf = szAddrsBuf;

		if (g_pPxchConfig->dwLogLevel >= PXCH_LOG_LEVEL_DEBUG) {
			for (pResultCast = pResolvedResultCast; pResultCast; pResultCast = pResultCast->ai_next) {
				StringCchPrintfExW(pszAddrsBuf, _countof(szAddrsBuf) - (pszAddrsBuf - szAddrsBuf), &pszAddrsBuf, NULL, 0, L"%ls%ls", pResultCast == pResolvedResultCast ? L"" : L", ", FormatHostPortToStr(pResultCast->ai_addr, (int)pResultCast->ai_addrlen));
			}
			FUNCIPCLOGD(L"Ws2_32.dll GetAddrInfoW(%ls, %ls, ...) result %p: %ls", pNodeName, pServiceName, pResolvedResultCast, szAddrsBuf);
		}

		if (pResolvedResultCast == NULL) {
			bShouldReturnFakeIp = FALSE;
			bShouldReturnResolvedResult = TRUE;
		}
	}

	if (bShouldUseHostsResult) {
		pResolvedResultCast = NULL;
		IpPortResolvedByHosts.CommonHeader.wPort = HostPort.CommonHeader.wPort;

		HostnameAndIpPortsToAddrInfo_WillAllocate(
			&pResolvedResultCast,
			&Hostname,
			1,
			&IpPortResolvedByHosts,
			!!(pHintsCast->ai_flags & AI_CANONNAME),
			pHintsCast->ai_socktype,
			pHintsCast->ai_protocol
		);
		
		FUNCIPCLOGD(L"Ws2_32.dll GetAddrInfoW(%ls, %ls, AF%#010x, FL%#010x, ST%#010x, PT%#010x): resolved by hosts: %ls", pNodeName, pServiceName, pHintsCast->ai_family, pHintsCast->ai_flags, pHintsCast->ai_socktype, pHintsCast->ai_protocol, FormatHostPortToStr(&IpPortResolvedByHosts, sizeof(IpPortResolvedByHosts)));

		iWSALastError = NO_ERROR;
		dwLastError = NO_ERROR;
		iReturn = 0;
	}

	if (bShouldReturnFakeIp) {
		PXCH_UINT32 cbMessageSize;
		PXCH_UINT32 cbRespMessageSize;
		PXCH_UINT32 dwIpNum;
		ADDRINFOW* pNewAddrInfoWResult;
		int iIpFamilyAllowed;
		PXCH_IP_PORT* pFakeIpPorts;
		BOOL bShouldReturnIpv4 = FALSE;
		BOOL bShouldReturnIpv6 = FALSE;

		AddrInfoToIps(&dwIpNum, Ips, pResolvedResultCast, TRUE);

		if (bShouldUseResolvedResult) {
			// We should not return fake IPs with types that are not in resolved IPs, because we know later we will connect to one of the resolved IPs
			for (dw = 0; dw < dwIpNum; dw++) {
				if (Ips[dw].CommonHeader.wTag == PXCH_HOST_TYPE_IPV4) {
					bShouldReturnIpv4 = TRUE;
				}
				if (Ips[dw].CommonHeader.wTag == PXCH_HOST_TYPE_IPV6) {
					bShouldReturnIpv6 = TRUE;
				}
			}
		} else {
			// We can return fake IPs with requested types, because locally resolved IPs are not used
			bShouldReturnIpv4 = (pHintsCast->ai_family == AF_UNSPEC || pHintsCast->ai_family == AF_INET);
			bShouldReturnIpv6 = (pHintsCast->ai_family == AF_UNSPEC || pHintsCast->ai_family == AF_INET6);
		}

		if ((dwLastError = HostnameAndIpsToMessage(chMessageBuf, &cbMessageSize, GetCurrentProcessId(), &Hostname, g_pPxchConfig->dwWillMapResolvedIpToHost, dwIpNum, Ips, dwTarget)) != NO_ERROR) goto err;

		if ((dwLastError = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, (PXCH_UINT32*)&cbRespMessageSize)) != NO_ERROR) goto err;

		if ((dwLastError = MessageToHostnameAndIps(NULL, NULL, NULL, NULL /*Must be 2*/, (PXCH_IP_PORT*)FakeIpPorts, NULL, chRespMessageBuf, cbRespMessageSize)) != NO_ERROR) goto err;

		FakeIpPorts[0].CommonHeader.wPort = HostPort.CommonHeader.wPort;
		FakeIpPorts[1].CommonHeader.wPort = HostPort.CommonHeader.wPort;

		iIpFamilyAllowed = 0;
		pFakeIpPorts = FakeIpPorts + 1;

		if (g_pPxchConfig->dwWillFirstTunnelUseIpv4 && bShouldReturnIpv4) {
			iIpFamilyAllowed++;
			pFakeIpPorts--;
		}
		if (g_pPxchConfig->dwWillFirstTunnelUseIpv6 && bShouldReturnIpv6) {
			iIpFamilyAllowed++;
		}
		HostnameAndIpPortsToAddrInfo_WillAllocate(
			&pNewAddrInfoWResult,
			&Hostname,
			iIpFamilyAllowed,
			pFakeIpPorts,
			!!(pHintsCast->ai_flags & AI_CANONNAME),
			pResolvedResultCast ? pResolvedResultCast->ai_socktype : pHintsCast->ai_socktype,
			pResolvedResultCast ? pResolvedResultCast->ai_protocol : pHintsCast->ai_protocol
		);

		*ppResultCast = pNewAddrInfoWResult;
		if (*ppResultCast == NULL) {
			dwLastError = ERROR_NOT_FOUND;
			goto err;
		}
		if (pResolvedResultCast) {
			ProxyWs2_32_FreeAddrInfoW(pResolvedResultCast);
			pResolvedResultCast = NULL;
		}

		iWSALastError = NO_ERROR;
		dwLastError = NO_ERROR;
		iReturn = 0;
	}

	if (bShouldReturnResolvedResult) {
		*ppResultCast = pResolvedResultCast;
	}

	if (bShouldReturnHostsResult) {
		*ppResultCast = pResolvedResultCast;
		iWSALastError = NO_ERROR;
		dwLastError = NO_ERROR;
		iReturn = 0;
	}

	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iReturn;

err:
	if (pResolvedResultCast) orig_fpWs2_32_FreeAddrInfoW(pResolvedResultCast);
	if (pQueryPortAddrInfo) orig_fpWs2_32_FreeAddrInfoW(pQueryPortAddrInfo);
	if (pRequeryAddrInfo) orig_fpWs2_32_FreeAddrInfoW(pRequeryAddrInfo);
	WSASetLastError(WSAHOST_NOT_FOUND);
	SetLastError(dwLastError);
	return WSAHOST_NOT_FOUND;
}

// Hook GetAddrInfoExA

PROXY_FUNC2(Ws2_32, GetAddrInfoExA)
{
	FUNCIPCLOGD(L"Ws2_32.dll GetAddrInfoExA() called");

	return orig_fpWs2_32_GetAddrInfoExA(pName, pServiceName, dwNameSpace, lpNspId, hints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpHandle);
}

// Hook GetAddrInfoExW

PROXY_FUNC2(Ws2_32, GetAddrInfoExW)
{
	FUNCIPCLOGD(L"Ws2_32.dll GetAddrInfoExW() called");

	return orig_fpWs2_32_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, hints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpHandle);
}

// Hook freeaddrinfo

PROXY_FUNC2(Ws2_32, freeaddrinfo)
{
	FUNCIPCLOGD(L"Ws2_32.dll freeaddrinfo() called");
	PXCH_DO_IN_CRITICAL_SECTION_RETURN_VOID{
		void* pHeapAllocatedPointerElement;

		for (pHeapAllocatedPointerElement = utarray_front(g_arrHeapAllocatedPointers); pHeapAllocatedPointerElement != NULL; pHeapAllocatedPointerElement = utarray_next(g_arrHeapAllocatedPointers, pHeapAllocatedPointerElement)) {
			// FUNCIPCLOGI(L"%p: Checking %p ~%p", pAddrInfo, *(void**)pHeapAllocatedPointerElement, (void*)(~(PXCH_UINT_PTR)(*(void**)pHeapAllocatedPointerElement)));
			if (~(PXCH_UINT_PTR)(*(void**)pHeapAllocatedPointerElement) == (PXCH_UINT_PTR)pAddrInfo) {
				// FUNCIPCLOGI(L"This pointer has been freed before");
				goto lock_after_critical_section;
			}

			if (*(void**)pHeapAllocatedPointerElement == pAddrInfo) {
				// FUNCIPCLOGI(L"%p: This pointer is now freed", pAddrInfo);
				HeapFree(GetProcessHeap(), 0, pAddrInfo);
				*(void**)pHeapAllocatedPointerElement = (void*)(~(PXCH_UINT_PTR)(*(void**)pHeapAllocatedPointerElement));
				goto lock_after_critical_section;
			}
		}

		HeapUnlock(GetProcessHeap());	// go out of critical section
		// FUNCIPCLOGI(L"%p: This pointer is managed by winsock", pAddrInfo);
		orig_fpWs2_32_freeaddrinfo(pAddrInfo);
		return;
	}
}

// Hook FreeAddrInfoW

PROXY_FUNC2(Ws2_32, FreeAddrInfoW)
{
	FUNCIPCLOGD(L"Ws2_32.dll FreeAddrInfoW() called");
	PXCH_DO_IN_CRITICAL_SECTION_RETURN_VOID{
		void* pHeapAllocatedPointerElement;

		for (pHeapAllocatedPointerElement = utarray_back(g_arrHeapAllocatedPointers); pHeapAllocatedPointerElement != NULL; pHeapAllocatedPointerElement = utarray_prev(g_arrHeapAllocatedPointers, pHeapAllocatedPointerElement)) {
			// FUNCIPCLOGI(L"%p: Checking %p ~%p", pAddrInfo, *(void**)pHeapAllocatedPointerElement, (void*)(~(PXCH_UINT_PTR)(*(void**)pHeapAllocatedPointerElement)));
			if (~(PXCH_UINT_PTR)(*(void**)pHeapAllocatedPointerElement) == (PXCH_UINT_PTR)pAddrInfo) {
				// FUNCIPCLOGI(L"This pointer has been freed before");
				goto lock_after_critical_section;
			}

			if (*(void**)pHeapAllocatedPointerElement == pAddrInfo) {
				// FUNCIPCLOGI(L"%p: This pointer is now freed", pAddrInfo);
				HeapFree(GetProcessHeap(), 0, pAddrInfo);
				*(void**)pHeapAllocatedPointerElement = (void*)(~(PXCH_UINT_PTR)(*(void**)pHeapAllocatedPointerElement));
				goto lock_after_critical_section;
			}
		}

		HeapUnlock(GetProcessHeap());	// go out of critical section
		orig_fpWs2_32_FreeAddrInfoW(pAddrInfo);
		return;
	}
}

// Hook FreeAddrInfoExA

PROXY_FUNC2(Ws2_32, FreeAddrInfoExA_)
{
	FUNCIPCLOGD(L"Ws2_32.dll FreeAddrInfoExA() called");

	orig_fpWs2_32_FreeAddrInfoExA_(pAddrInfoEx);
}


// Hook FreeAddrInfoW

PROXY_FUNC2(Ws2_32, FreeAddrInfoExW)
{
	FUNCIPCLOGD(L"Ws2_32.dll FreeAddrInfoExW() called");

	orig_fpWs2_32_FreeAddrInfoExW(pAddrInfoEx);
}


// Hook getnameinfo

PROXY_FUNC2(Ws2_32, getnameinfo)
{
	FUNCIPCLOGD(L"Ws2_32.dll getnameinfo() called");

	return orig_fpWs2_32_getnameinfo(pSockaddr, SockaddrLength, pNodeBuffer, NodeBufferSize, pServiceBuffer, ServiceBufferSize, Flags);
}

// Hook GetNameInfoW

PROXY_FUNC2(Ws2_32, GetNameInfoW)
{
	FUNCIPCLOGD(L"Ws2_32.dll GetNameInfoW() called");

	return orig_fpWs2_32_GetNameInfoW(pSockaddr, SockaddrLength, pNodeBuffer, NodeBufferSize, pServiceBuffer, ServiceBufferSize, Flags);
}