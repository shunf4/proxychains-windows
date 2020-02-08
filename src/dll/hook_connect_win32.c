#define PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#define PXCH_INCLUDE_WSOCK_UTILS
#include "includes_win32.h"
#include "common_win32.h"
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Mswsock.h>
#include <Shlwapi.h>
#include <stdlib.h>
#include <strsafe.h>
#include "hookdll_win32.h"
#include "hookdll_interior_win32.h"
#include "log_generic.h"
#include <MinHook.h>

#include "proxy_core.h"

#ifndef __CYGWIN__
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")
#endif

static PXCH_PROXY_DIRECT_DATA g_proxyDirect;

typedef struct _PXCH_WS2_32_TEMP_DATA {
	DWORD iConnectLastError;
	int iConnectWSALastError;
	int iConnectReturn;
} PXCH_WS2_32_TEMP_DATA;

typedef struct _PXCH_MSWSOCK_TEMP_DATA {
	DWORD iConnectLastError;
	int iConnectWSALastError;
	BOOL bConnectReturn;
} PXCH_MSWSOCK_TEMP_DATA;

static BOOL ResolveByHostsFile(PXCH_IP_ADDRESS* pIp, const PXCH_HOSTNAME* pHostname)
{
	PXCH_UINT32 i;
	for (i = 0; i < g_pPxchConfig->dwHostsEntryNum; i++) {
		if (StrCmpW(PXCHCONFIG_HOSTS_ENTRY_ARR_G[i].Hostname.szValue, pHostname->szValue) == 0) {
			if (pIp) *pIp = PXCHCONFIG_HOSTS_ENTRY_ARR_G[i].Ip;
			break;
		}
	}
	return i != g_pPxchConfig->dwHostsEntryNum;
}

static BOOL WillProxyByRule(BOOL* pbMatchedHostnameRule, BOOL* pbMatchedIpRule, BOOL* pbMatchedPortRule, BOOL* pbMatchedFinalRule, const PXCH_HOST_PORT* pHostPort, BOOL bDefault)
{
	unsigned int i;
	PXCH_RULE* pRule;
	BOOL bDummyMatched1;
	BOOL bDummyMatched2;
	BOOL bDummyMatched3;
	BOOL bDummyMatched4;

	if (pbMatchedHostnameRule == NULL) pbMatchedHostnameRule = &bDummyMatched1;
	if (pbMatchedIpRule == NULL) pbMatchedIpRule = &bDummyMatched2;
	if (pbMatchedPortRule == NULL) pbMatchedPortRule = &bDummyMatched2;
	if (pbMatchedFinalRule == NULL) pbMatchedFinalRule = &bDummyMatched2;

	*pbMatchedHostnameRule = FALSE;
	*pbMatchedIpRule = FALSE;
	*pbMatchedPortRule = FALSE;
	*pbMatchedFinalRule = FALSE;

	for (i = 0; i < g_pPxchConfig->dwRuleNum; i++) {
		pRule = &PXCHCONFIG_RULE_ARR(g_pPxchConfig)[i];

		if (RuleIsType(FINAL, *pRule)) {
			return (BOOL)pRule->iWillProxy;
		}

		if (pRule->HostPort.CommonHeader.wPort && pHostPort->CommonHeader.wPort) {
			if (pRule->HostPort.CommonHeader.wPort != pHostPort->CommonHeader.wPort) {
				// Mismatch
				continue;
			} else if (RuleIsType(PORT, *pRule)) {
				// Match
				*pbMatchedPortRule = TRUE;
				return (BOOL)pRule->iWillProxy;
			}
		}

		if (HostIsIp(*pHostPort) && RuleIsType(IP_CIDR, *pRule)) {
			if (HostIsType(IPV4, *pHostPort) && HostIsType(IPV4, pRule->HostPort)) {
				const struct sockaddr_in* pIpv4 = (const struct sockaddr_in*)pHostPort;
				const struct sockaddr_in* pRuleIpv4 = (const struct sockaddr_in*) & pRule->HostPort;

				// long is always 32-bit
				PXCH_UINT32 dwMask = htonl(~(((PXCH_UINT64)1 << (32 - pRule->dwCidrPrefixLength)) - 1));

				if ((pIpv4->sin_addr.s_addr & dwMask) == (pRuleIpv4->sin_addr.s_addr & dwMask)) {
					// Match
					*pbMatchedIpRule = TRUE;
					return (BOOL)pRule->iWillProxy;
				}
			}

			if (HostIsType(IPV6, *pHostPort) && HostIsType(IPV6, pRule->HostPort)) {
				const struct sockaddr_in6* pIpv6 = (const struct sockaddr_in6*)pHostPort;
				const struct sockaddr_in6* pRuleIpv6 = (const struct sockaddr_in6*) & pRule->HostPort;

				struct {
					PXCH_UINT64 First64;
					PXCH_UINT64 Last64;
				} MaskInvert, MaskedIpv6, MaskedRuleIpv6, *pIpv6AddrInQwords;

				PXCH_UINT32 dwToShift = pRule->dwCidrPrefixLength > 128 ? 0 : 128 - pRule->dwCidrPrefixLength;
				PXCH_UINT32 dwShift1 = dwToShift >= 64 ? 64 : dwToShift;
				PXCH_UINT32 dwShift2 = dwToShift >= 64 ? (dwToShift - 64) : 0;

				MaskInvert.Last64 = dwShift1 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift1) - 1);
				MaskInvert.First64 = dwShift2 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift2) - 1);

				if (LITTLEENDIAN) {
					MaskInvert.Last64 = _byteswap_uint64(MaskInvert.Last64);
					MaskInvert.First64 = _byteswap_uint64(MaskInvert.First64);
				}

				pIpv6AddrInQwords = (void*)&pIpv6->sin6_addr;
				MaskedIpv6 = *pIpv6AddrInQwords;
				MaskedIpv6.First64 &= ~MaskInvert.First64;
				MaskedIpv6.Last64 &= ~MaskInvert.Last64;

				pIpv6AddrInQwords = (void*)&pRuleIpv6->sin6_addr;
				MaskedRuleIpv6 = *pIpv6AddrInQwords;
				MaskedRuleIpv6.First64 &= ~MaskInvert.First64;
				MaskedRuleIpv6.Last64 &= ~MaskInvert.Last64;

				if (RtlCompareMemory(&MaskedIpv6, &MaskedRuleIpv6, sizeof(MaskedIpv6)) == sizeof(MaskedIpv6)) {
					// Match
					*pbMatchedIpRule = TRUE;
					return (BOOL)pRule->iWillProxy;
				}
			}
		}

		if (HostIsType(HOSTNAME, *pHostPort) && RuleIsType(DOMAIN, *pRule)) {
			if (StrCmpIW(pHostPort->HostnamePort.szValue, pRule->HostPort.HostnamePort.szValue) == 0) {
				// Match
				*pbMatchedHostnameRule = TRUE;
				return (BOOL)pRule->iWillProxy;
			}
		}

		if (HostIsType(HOSTNAME, *pHostPort) && RuleIsType(DOMAIN_SUFFIX, *pRule)) {
			SIZE_T cchLength = 0;
			SIZE_T cchRuleLength = 0;
			StringCchLengthW(pHostPort->HostnamePort.szValue, _countof(pHostPort->HostnamePort.szValue), &cchLength);
			StringCchLengthW(pRule->HostPort.HostnamePort.szValue, _countof(pRule->HostPort.HostnamePort.szValue), &cchRuleLength);

			if (cchRuleLength <= cchLength) {
				if (StrCmpIW(pHostPort->HostnamePort.szValue + (cchLength - cchRuleLength), pRule->HostPort.HostnamePort.szValue) == 0) {
					// Match
					*pbMatchedHostnameRule = TRUE;
					return (BOOL)pRule->iWillProxy;
				}
			}
		}

		if (HostIsType(HOSTNAME, *pHostPort) && RuleIsType(DOMAIN_KEYWORD, *pRule)) {
			if (StrStrW(pHostPort->HostnamePort.szValue, pRule->HostPort.HostnamePort.szValue) == 0) {
				// Match
				*pbMatchedHostnameRule = TRUE;
				return (BOOL)pRule->iWillProxy;
			}
		}
	}

	return bDefault;
}


int Ws2_32_OriginalConnect(void* pTempData, PXCH_UINT_PTR s, const void* pAddr, int iAddrLen)
{
	int iReturn;
	int iWSALastError;
	int iLastError;
	PXCH_WS2_32_TEMP_DATA* pWs2_32_TempData = pTempData;

	iReturn = orig_fpWs2_32_connect(s, pAddr, iAddrLen);
	iWSALastError = WSAGetLastError();
	iLastError = GetLastError();

	if (pWs2_32_TempData) {
		pWs2_32_TempData->iConnectReturn = iReturn;
		pWs2_32_TempData->iConnectWSALastError = iWSALastError;
		pWs2_32_TempData->iConnectLastError = iLastError;
	}

	WSASetLastError(iWSALastError);
	SetLastError(iLastError);
	return iReturn;
}

int Ws2_32_BlockConnect(void* pTempData, PXCH_UINT_PTR s, const void* pAddr, int iAddrLen)
{
	int iReturn;
	int iWSALastError;
	int iLastError;
	fd_set wfds;
	PXCH_WS2_32_TEMP_DATA* pWs2_32_TempData = pTempData;

	iReturn = orig_fpWs2_32_connect(s, pAddr, iAddrLen);
	iWSALastError = WSAGetLastError();
	iLastError = GetLastError();

	if (pWs2_32_TempData) {
		pWs2_32_TempData->iConnectReturn = iReturn;
		pWs2_32_TempData->iConnectWSALastError = iWSALastError;
		pWs2_32_TempData->iConnectLastError = iLastError;
	}

	if (iReturn) {
		if (iWSALastError == WSAEWOULDBLOCK) {
			FUNCIPCLOGD(L"ws2_32.dll connect(%d, %ls, %d) : this socket is nonblocking and it didn't finish instantly.", s, FormatHostPortToStr(pAddr, iAddrLen), iAddrLen);
		}
		else goto err_connect;
	}

	FD_ZERO(&wfds);
	FD_SET(s, &wfds);
	FUNCIPCLOGD(L"ws2_32.dll connect(%d, %ls, %d) : selecting...", s, FormatHostPortToStr(pAddr, iAddrLen), iAddrLen);
	iReturn = select(-1, NULL, &wfds, NULL, NULL);
	FUNCIPCLOGD(L"ws2_32.dll connect(%d, %ls, %d) : after select.", s, FormatHostPortToStr(pAddr, iAddrLen), iAddrLen);
	iWSALastError = WSAGetLastError();
	iLastError = GetLastError();
	if (iReturn == SOCKET_ERROR) goto err_select;
	if (iReturn != 1 || !FD_ISSET(s, &wfds)) goto err_select_unexpected;

	WSASetLastError(NO_ERROR);
	SetLastError(NO_ERROR);
	return 0;

err_select_unexpected:
	FUNCIPCLOGW(L"select() returns unexpected value!");
	goto err_return;

err_select:
	FUNCIPCLOGW(L"select() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_connect:
	FUNCIPCLOGW(L"connect() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_return:
	WSASetLastError(iWSALastError);
	SetLastError(iLastError);
	return SOCKET_ERROR;
}

int Ws2_32_LoopSend(void* pTempData, PXCH_UINT_PTR s, const char* SendBuf, int iLength)
{
	int iReturn;
	int iWSALastError;
	int iLastError;
	fd_set wfds;
	const char* pSendBuf = SendBuf;
	int iRemaining = iLength;

	while (iRemaining > 0) {
		FD_ZERO(&wfds);
		FD_SET(s, &wfds);
		iReturn = select(-1, NULL, &wfds, NULL, NULL);
		iWSALastError = WSAGetLastError();
		iLastError = GetLastError();
		if (iReturn == SOCKET_ERROR) goto err_select;
		if (iReturn != 1 || !FD_ISSET(s, &wfds)) goto err_select_unexpected;

		iReturn = send(s, pSendBuf, iRemaining, 0);
		if (iReturn == SOCKET_ERROR) goto err_send;
		if (iReturn < iLength) {
			FUNCIPCLOGD(L"send() only sent %d/%d bytes", iReturn, iLength);
		} else if (iReturn == iLength) {
			FUNCIPCLOGD(L"send() sent %d/%d bytes", iReturn, iLength);
		} else goto err_send_unexpected;

		pSendBuf += iReturn;
		iRemaining -= iReturn;
	}

	SetLastError(NO_ERROR);
	WSASetLastError(NO_ERROR);
	return 0;

err_send_unexpected:
	FUNCIPCLOGW(L"send() occurs unexpected error!");
	goto err_return;

err_select_unexpected:
	FUNCIPCLOGW(L"select() returns unexpected value!");
	goto err_return;

err_send:
	FUNCIPCLOGW(L"send() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_select:
	FUNCIPCLOGW(L"select() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_return:
	WSASetLastError(iWSALastError);
	SetLastError(iLastError);
	return SOCKET_ERROR;
}

int Ws2_32_LoopRecv(void* pTempData, PXCH_UINT_PTR s, char* RecvBuf, int iLength)
{
	int iReturn;
	int iWSALastError;
	int iLastError;
	fd_set rfds;
	char* pRecvBuf = RecvBuf;
	int iRemaining = iLength;

	while (iRemaining > 0) {
		FD_ZERO(&rfds);
		FD_SET(s, &rfds);
		iReturn = select(-1, &rfds, NULL, NULL, NULL);
		iWSALastError = WSAGetLastError();
		iLastError = GetLastError();
		if (iReturn == SOCKET_ERROR) goto err_select;
		if (iReturn != 1 || !FD_ISSET(s, &rfds)) goto err_select_unexpected;

		iReturn = recv(s, pRecvBuf, iRemaining, 0);
		if (iReturn == SOCKET_ERROR) goto err_recv;
		if (iReturn < iLength) {
			FUNCIPCLOGD(L"recv() only received %d/%d bytes", iReturn, iLength);
		} else if (iReturn == iLength) {
			FUNCIPCLOGD(L"recv() received %d/%d bytes", iReturn, iLength);
		} else goto err_recv_unexpected;

		pRecvBuf += iReturn;
		iRemaining -= iReturn;
	}

	SetLastError(NO_ERROR);
	WSASetLastError(NO_ERROR);
	return 0;

err_recv_unexpected:
	FUNCIPCLOGW(L"recv() occurs unexpected error!");
	goto err_return;

err_select_unexpected:
	FUNCIPCLOGW(L"select() returns unexpected value!");
	goto err_return;

err_recv:
	FUNCIPCLOGW(L"recv() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_select:
	FUNCIPCLOGW(L"select() error: %ls", FormatErrorToStr(iWSALastError));
	goto err_return;

err_return:
	WSASetLastError(iWSALastError);
	SetLastError(iLastError);
	return SOCKET_ERROR;
}

PXCHDLL_API int Ws2_32_DirectConnect(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen)
{
	if (HostIsType(HOSTNAME, *pHostPort) || HostIsType(INVALID, *pHostPort)) {
		FUNCIPCLOGW(L"Error connecting directly: address is hostname or invalid (%#06hx).", *(const PXCH_UINT16*)pHostPort);
		WSASetLastError(WSAEAFNOSUPPORT);
		return SOCKET_ERROR;
	}
	FUNCIPCLOGI(L"Ws2_32_DirectConnect(%ls)", FormatHostPortToStr(pHostPort, iAddrLen));
	return Ws2_32_BlockConnect(pTempData, s, pHostPort, iAddrLen);
}

PXCHDLL_API int Ws2_32_Socks5Connect(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen)
{
	if (!HostIsIp(*pHostPort) && !HostIsType(HOSTNAME, *pHostPort)) {
		FUNCIPCLOGW(L"Error connecting through Socks5: address is neither hostname nor ip.");
		WSASetLastError(WSAEAFNOSUPPORT);
		return SOCKET_ERROR;
	}

	const struct sockaddr_in* SockAddrIpv4;
	// const struct sockaddr_in6* SockAddrIpv6;
	// const PXCH_HOSTNAME_PORT* AddrHostName;
	int iResult;
	char SendBuf[256];
	char RecvBuf[256];

	FUNCIPCLOGI(L"Ws2_32_Socks5Connect(%ls)", FormatHostPortToStr(pHostPort, iAddrLen));

	if (HostIsType(IPV4, *pHostPort)) {
		SockAddrIpv4 = (const struct sockaddr_in*)pHostPort;
		
		// Connect
		CopyMemory(SendBuf, "\05\01\00\x01\xFF\xFF\xFF\xFF\xEE\xEE", 10);
		CopyMemory(SendBuf + 4, &SockAddrIpv4->sin_addr, 4);
		CopyMemory(SendBuf + 8, &SockAddrIpv4->sin_port, 2);
		if ((iResult = Ws2_32_LoopSend(pTempData, s, SendBuf, 10)) == SOCKET_ERROR) goto err_general;
		if ((iResult = Ws2_32_LoopRecv(pTempData, s, RecvBuf, 10)) == SOCKET_ERROR) goto err_general;
		if (RecvBuf[1] != '\00' || RecvBuf[3] != '\01') goto err_data_invalid_2;
	} else goto err_not_supported;

	SetLastError(NO_ERROR);
	WSASetLastError(NO_ERROR);
	return 0;

err_not_supported:
	FUNCIPCLOGW(L"Error connecting through Socks5: addresses other than Ipv4 not implemented.");
	iResult = SOCKET_ERROR;
	SetLastError(ERROR_NOT_SUPPORTED);
	WSASetLastError(WSAEAFNOSUPPORT);
	goto err_general;

err_data_invalid_2:
	FUNCIPCLOGW(L"Socks5 data format invalid: server disallows this connection");
	goto err_general;

err_general:
	shutdown(s, SD_BOTH);
	return iResult;
}

PXCHDLL_API int Ws2_32_Socks5Handshake(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */)
{
	int iResult;
	char RecvBuf[256];

	FUNCIPCLOGI(L"Ws2_32_Socks5Handshake()");

	if ((iResult = Ws2_32_LoopSend(pTempData, s, "\05\01\00", 3)) == SOCKET_ERROR) goto err_general;
	if ((iResult = Ws2_32_LoopRecv(pTempData, s, RecvBuf, 2)) == SOCKET_ERROR) goto err_general;
	if (RecvBuf[1] != '\00') goto err_data_invalid_1;

	SetLastError(NO_ERROR);
	WSASetLastError(NO_ERROR);
	return 0;

err_data_invalid_1:
	// TODO: Fix later
	FUNCIPCLOGW(L"Socks5 data format invalid: server disallows NoAuth");
	goto err_general;

err_general:
	shutdown(s, SD_BOTH);
	return iResult;
}

int Ws2_32_GenericConnectTo(void* pTempData, PXCH_UINT_PTR s, PPXCH_CHAIN pChain, const PXCH_HOST_PORT* pHostPort, int iAddrLen)
{
	FUNCIPCLOGI(L"Ws2_32_GenericConnectTo(%ls)", FormatHostPortToStr(pHostPort, iAddrLen));
	if (*pChain == NULL) {
		SetProxyType(DIRECT, g_proxyDirect);
		g_proxyDirect.Ws2_32_FpConnect = &Ws2_32_DirectConnect;
		g_proxyDirect.Ws2_32_FpHandshake = NULL;

		PXCH_CHAIN_NODE* pNewNodeDirect;

		pNewNodeDirect = HeapAlloc(GetProcessHeap(), 0, sizeof(PXCH_CHAIN_NODE));
		pNewNodeDirect->pProxy = (PXCH_PROXY_DATA*)&g_proxyDirect;
		pNewNodeDirect->prev = NULL;
		pNewNodeDirect->next = NULL;

		CDL_APPEND(*pChain, pNewNodeDirect);
	}

	int iReturn;
	PXCH_CHAIN_NODE* pChainLastNode;
	PXCH_PROXY_DATA* pProxy;

	pChainLastNode = (*pChain)->prev;	// Last
	pProxy = pChainLastNode->pProxy;

	iReturn = pProxy->CommonHeader.Ws2_32_FpConnect(pTempData, s, pProxy, pHostPort, iAddrLen);
	return iReturn;
}

int Ws2_32_GenericTunnelTo(void* pTempData, PXCH_UINT_PTR s, PPXCH_CHAIN pChain, PXCH_PROXY_DATA* pProxy)
{
	int iLastError;
	int iWSALastError;
	int iReturn;
	PXCH_CHAIN_NODE* pNewNode;

	FUNCIPCLOGI(L"Ws2_32_GenericTunnelTo(%ls)", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));
	iReturn = Ws2_32_GenericConnectTo(pTempData, s, pChain, &pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen);
	iWSALastError = WSAGetLastError();
	iLastError = GetLastError();
	if (iReturn) goto err_connect;
	FUNCIPCLOGI(L"Ws2_32_GenericTunnelTo(%ls): after Ws2_32_GenericConnectTo()", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));

	pNewNode = HeapAlloc(GetProcessHeap(), 0, sizeof(PXCH_CHAIN_NODE));
	pNewNode->pProxy = pProxy;

	CDL_APPEND((*pChain), pNewNode);

	iReturn = pNewNode->pProxy->CommonHeader.Ws2_32_FpHandshake(pTempData, s, pProxy);
	iWSALastError = WSAGetLastError();
	iLastError = GetLastError();
	if (iReturn) goto err_handshake;
	FUNCIPCLOGI(L"Ws2_32_GenericTunnelTo(%ls): after pProxy->CommonHeader.Ws2_32_FpHandshake()", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));

	WSASetLastError(NO_ERROR);
	SetLastError(NO_ERROR);
	return iReturn;

err_connect:
	FUNCIPCLOGI(L"Ws2_32_GenericTunnelTo(%ls) connect failed!", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));
	goto err_return;
err_handshake:
	FUNCIPCLOGI(L"Ws2_32_GenericTunnelTo(%ls) handshake failed!", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iAddrLen));
err_return:
	WSASetLastError(iWSALastError);
	SetLastError(iLastError);
	return iReturn;
}

// Hook connect

PROXY_FUNC2(Ws2_32, connect)
{
	// SOCKET real_s = s;
	const PXCH_HOST_PORT* pHostPort = name;
	unsigned int i;
	int iReturn = 0;
	int iLastError;
	int iWSALastError;
	BOOL bWillProxy;
	PXCH_CHAIN Chain = NULL;
	PXCH_CHAIN_NODE* ChainNode = NULL;
	PXCH_WS2_32_TEMP_DATA TempData;

	RestoreChildData();

	FUNCIPCLOGI(L"ws2_32.dll connect(%d, %ls, %d) called", s, FormatHostPortToStr(name, namelen), namelen);

	bWillProxy = WillProxyByRule(NULL, NULL, NULL, NULL, pHostPort, FALSE);
	
	if (!bWillProxy) {
		iReturn = Ws2_32_OriginalConnect(&TempData, s, name, namelen);
		goto success_revert_connect_errcode_end;
	}

	for (i = 0; i < g_pPxchConfig->dwProxyNum; i++) {
		if ((iReturn = Ws2_32_GenericTunnelTo(&TempData, s, &Chain, &PXCHCONFIG_PROXY_ARR(g_pPxchConfig)[i])) == SOCKET_ERROR) goto record_error_end;
	}
	if ((iReturn = Ws2_32_GenericConnectTo(&TempData, s, &Chain, name, namelen)) == SOCKET_ERROR) goto record_error_end;

success_revert_connect_errcode_end:
	iWSALastError = TempData.iConnectWSALastError;
	iLastError = TempData.iConnectLastError;
	iReturn = TempData.iConnectReturn;
	goto end;

record_error_end:
	iWSALastError = WSAGetLastError();
	iLastError = GetLastError();

end:
	FUNCIPCLOGI(L"ws2_32.dll connect(%d, %ls, %d) proxied: %d", s, FormatHostPortToStr(name, namelen), namelen, bWillProxy);
	if (bWillProxy) {
		CDL_FOREACH(Chain, ChainNode) {
			FUNCIPCLOGI(L"<> %ls", FormatHostPortToStr(&ChainNode->pProxy->CommonHeader.HostPort, ChainNode->pProxy->CommonHeader.iAddrLen));
		}
	}

	// TODO: free
	FUNCIPCLOGI(L"ws2_32.dll connect() ret: %d, wsa last error: %ls", iReturn, FormatErrorToStr(iWSALastError));
	WSASetLastError(iWSALastError);
	SetLastError(iLastError);
	return iReturn;
}


// Hook ConnectEx

Mswsock_ConnectEx_SIGN_WITH_PTEMPDATA(Mswsock_OriginalConnectEx)
{
	BOOL bReturn;
	int iWSALastError;
	int iLastError;
	PXCH_MSWSOCK_TEMP_DATA* pMswsock_TempData = pTempData;

	pMswsock_TempData->bConnectReturn = bReturn = orig_fpMswsock_ConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
	pMswsock_TempData->iConnectWSALastError = iWSALastError = WSAGetLastError();
	pMswsock_TempData->iConnectLastError = iLastError = GetLastError();

	WSASetLastError(iWSALastError);
	SetLastError(iLastError);
	return bReturn;
}

PROXY_FUNC2(Mswsock, ConnectEx)
{
	const PXCH_HOST_PORT* pHostPort = name;
	unsigned int i;
	int iReturn;
	BOOL bReturn;
	int iLastError;
	int iWSALastError;
	BOOL bWillProxy;
	PXCH_CHAIN Chain = NULL;
	PXCH_CHAIN_NODE* ChainNode = NULL;
	PXCH_MSWSOCK_TEMP_DATA TempData;

	RestoreChildData();

	FUNCIPCLOGI(L"mswsock.dll (FP)ConnectEx(%d, %ls, %d) called", s, FormatHostPortToStr(name, namelen), namelen);

	bWillProxy = WillProxyByRule(NULL, NULL, NULL, NULL, pHostPort, FALSE);
	
	if (!bWillProxy) {
		bReturn = Mswsock_OriginalConnectEx(&TempData, s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
		goto success_set_errcode_zero_end;
	}

	for (i = 0; i < g_pPxchConfig->dwProxyNum; i++) {
		if ((iReturn = Ws2_32_GenericTunnelTo(NULL, s, &Chain, &PXCHCONFIG_PROXY_ARR(g_pPxchConfig)[i])) == SOCKET_ERROR) goto record_error_end;
	}
	if ((iReturn = Ws2_32_GenericConnectTo(NULL, s, &Chain, name, namelen)) == SOCKET_ERROR) goto record_error_end;

success_set_errcode_zero_end:
	iWSALastError = NO_ERROR;
	iLastError = NO_ERROR;
	bReturn = TRUE;
	goto end;

record_error_end:
	iWSALastError = WSAGetLastError();
	iLastError = GetLastError();

end:
	FUNCIPCLOGI(L"mswsock.dll (FP)ConnectEx(%d, %ls, %d) proxied: %d", s, FormatHostPortToStr(name, namelen), namelen, bWillProxy);
	if (bWillProxy) {
		CDL_FOREACH(Chain, ChainNode) {
			FUNCIPCLOGI(L"<> %ls", FormatHostPortToStr(&ChainNode->pProxy->CommonHeader.HostPort, ChainNode->pProxy->CommonHeader.iAddrLen));
		}
	}

	// TODO: free
	FUNCIPCLOGI(L"mswsock.dll (FP)ConnectEx ret: %d, wsa last error: %ls", bReturn, FormatErrorToStr(iWSALastError));
	WSASetLastError(iWSALastError);
	SetLastError(iLastError);
	return bReturn;
}

// Hook WSAStartup

PROXY_FUNC2(Ws2_32, WSAStartup)
{
	int iReturn;
	FUNCIPCLOGI(L"Ws2_32.dll WSAStartup() called");
	iReturn = orig_fpWs2_32_WSAStartup(wVersionRequested, lpWSAData);
	if (iReturn == 0) {
		SOCKET DummySocket;
		GUID GuidConnectEx = WSAID_CONNECTEX;
		LPFN_CONNECTEX fpConnectEx = NULL;
		DWORD cb;

		DummySocket = socket(AF_INET, SOCK_STREAM, 0);
		if (DummySocket == INVALID_SOCKET) goto out;
		if (WSAIoctl(DummySocket, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidConnectEx, sizeof(GUID), &fpConnectEx, sizeof(LPFN_CONNECTEX), &cb, NULL, NULL) != 0) goto out;
		if (!fpConnectEx) goto out;

		CREATE_HOOK3_IFNOTNULL(Mswsock, ConnectEx, fpConnectEx);
		MH_EnableHook(fpConnectEx);
	}

out:
	return iReturn;
}

// Hook WSAConnect

PROXY_FUNC2(Ws2_32, WSAConnect)
{
	FUNCIPCLOGI(L"Ws2_32.dll WSAConnect() called");
	return orig_fpWs2_32_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

// Hook gethostbyname

PROXY_FUNC2(Ws2_32, gethostbyname)
{
	struct hostent* orig_pHostent;
	struct hostent* pHostent = PXCH_TLS_PTR_W32HOSTENT(g_dwTlsIndex);
	PXCH_UINT32** ppIp;
	int iWSALastError;
	DWORD dwLastError;
	int i;

	FUNCIPCLOGI(L"Ws2_32.dll gethostbyname(%S) called", name);

	orig_pHostent = orig_fpWs2_32_gethostbyname(name);
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();

	if (orig_pHostent->h_length != sizeof(PXCH_UINT32)) goto orig;

	CopyMemory(pHostent, orig_pHostent, sizeof(struct hostent));
	pHostent->h_addr_list = PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_AS_PPCHAR(g_dwTlsIndex);
	ppIp = PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST(g_dwTlsIndex);
	pHostent->h_aliases = (char**)PXCH_TLS_PTR_W32HOSTENT_ALIAS_PTR_LIST(g_dwTlsIndex);
	pHostent->h_name = *PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF(g_dwTlsIndex);
	
	ZeroMemory(ppIp, sizeof(PXCH_UINT32* [PXCH_TLS_W32HOSTENT_IP_NUM]));
	for (i = 0; orig_pHostent->h_addr_list[i] && i < PXCH_TLS_W32HOSTENT_IP_NUM; i++) {
		ppIp[i] = &PXCH_TLS_PTR_W32HOSTENT_IP_BUF(g_dwTlsIndex)[i];
		CopyMemory(&PXCH_TLS_PTR_W32HOSTENT_IP_BUF(g_dwTlsIndex)[i], orig_pHostent->h_addr_list[i], sizeof(PXCH_UINT32));
	}

	ZeroMemory(pHostent->h_aliases, sizeof(char* [PXCH_TLS_W32HOSTENT_ALIAS_NUM]));
	for (i = 0; orig_pHostent->h_aliases[i] && i < PXCH_TLS_W32HOSTENT_ALIAS_NUM; i++) {
		pHostent->h_aliases[i] = PXCH_TLS_PTR_W32HOSTENT_ALIAS_BUF(g_dwTlsIndex)[i];
		StringCchCopyA(PXCH_TLS_PTR_W32HOSTENT_ALIAS_BUF(g_dwTlsIndex)[i], _countof(PXCH_TLS_PTR_W32HOSTENT_ALIAS_BUF(g_dwTlsIndex)[i]), orig_pHostent->h_aliases[i]);
	}

	StringCchCopyA(*PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF(g_dwTlsIndex), _countof(*PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF(g_dwTlsIndex)), orig_pHostent->h_name);

	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return pHostent;

orig:
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return pHostent;
}

// Hook gethostbyaddr

PROXY_FUNC2(Ws2_32, gethostbyaddr)
{
	FUNCIPCLOGI(L"Ws2_32.dll gethostbyaddr() called");

	return orig_fpWs2_32_gethostbyaddr(addr, len, type);
}

// Hook getaddrinfo

PROXY_FUNC2(Ws2_32, getaddrinfo)
{
	const ADDRINFOA* pHintsCast = pHints;
	PADDRINFOA* ppResultCast = ppResult;
	int iResult;
	DWORD dwLastError;
	int iWSALastError;

	WCHAR szAddrsBuf[200];
	WCHAR* pszAddrsBuf;
	PADDRINFOA pResultCast;


	FUNCIPCLOGI(L"Ws2_32.dll getaddrinfo(%S, %S, AF%#010x, FL%#010x, ST%#010x, PT%#010x) called", pNodeName, pServiceName, pHintsCast ? pHintsCast->ai_family : -1, pHintsCast ? pHintsCast->ai_flags : -1, pHintsCast ? pHintsCast->ai_socktype : -1, pHintsCast ? pHintsCast->ai_protocol : -1);

	iResult = orig_fpWs2_32_getaddrinfo(pNodeName, pServiceName, pHints, ppResult);
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();

	szAddrsBuf[0] = L'\0';
	pszAddrsBuf = szAddrsBuf;

	for (pResultCast = (*ppResultCast); pResultCast; pResultCast = pResultCast->ai_next) {
		StringCchPrintfExW(pszAddrsBuf, _countof(szAddrsBuf) - (pszAddrsBuf - szAddrsBuf), &pszAddrsBuf, NULL, 0, L"%ls%ls", pResultCast == (*ppResultCast) ? L"" : L", ", FormatHostPortToStr(pResultCast->ai_addr, (int)pResultCast->ai_addrlen));
	}

	FUNCIPCLOGI(L"Ws2_32.dll getaddrinfo(%S, %S, ...) result: %ls", pNodeName, pServiceName, szAddrsBuf);

	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iResult;
}

// Hook GetAddrInfoW

PROXY_FUNC2(Ws2_32, GetAddrInfoW)
{
	ADDRINFOW DefaultHints;
	const ADDRINFOW* pHintsCast = pHints ? pHints : &DefaultHints;
	PADDRINFOW* ppResultCast = ppResult;
	int iResult;
	DWORD dwLastError;
	int iWSALastError;

	WCHAR szAddrsBuf[200];
	WCHAR* pszAddrsBuf;
	PADDRINFOW pResultCast;

	PXCH_HOST_PORT HostPort;
	PXCH_HOST_PORT Hostname;
	PXCH_IP_ADDRESS DummyAddress;
	BOOL bWillProxy;
	BOOL bMatchedHostnameRule;

	ADDRINFOW RequeryAddrInfoHint;
	ADDRINFOW RequeryAddrInfo;

	ZeroMemory(&DefaultHints, sizeof(DefaultHints));
	DefaultHints.ai_family = -1;
	DefaultHints.ai_flags = -1;
	DefaultHints.ai_socktype = -1;
	DefaultHints.ai_protocol = -1;

	FUNCIPCLOGI(L"Ws2_32.dll GetAddrInfoW(%ls, %ls, AF%#010x, FL%#010x, ST%#010x, PT%#010x) called", pNodeName, pServiceName, pHintsCast->ai_family, pHintsCast->ai_flags, pHintsCast->ai_socktype, pHintsCast->ai_protocol);

	iResult = orig_fpWs2_32_GetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
	iWSALastError = WSAGetLastError();
	dwLastError = GetLastError();

	szAddrsBuf[0] = L'\0';
	pszAddrsBuf = szAddrsBuf;

	for (pResultCast = (*ppResultCast); pResultCast; pResultCast = pResultCast->ai_next) {
		StringCchPrintfExW(pszAddrsBuf, _countof(szAddrsBuf) - (pszAddrsBuf - szAddrsBuf), &pszAddrsBuf, NULL, 0, L"%ls%ls", pResultCast == (*ppResultCast) ? L"" : L", ", FormatHostPortToStr(pResultCast->ai_addr, (int)pResultCast->ai_addrlen));
	}

	FUNCIPCLOGI(L"Ws2_32.dll GetAddrInfoW(%ls, %ls, ...) result: %ls", pNodeName, pServiceName, szAddrsBuf);

	DefaultHints.ai_family = AF_UNSPEC;
	DefaultHints.ai_flags = 0;
	DefaultHints.ai_socktype = SOCK_STREAM;
	DefaultHints.ai_protocol = IPPROTO_TCP;

	ZeroMemory(&RequeryAddrInfoHint, sizeof(RequeryAddrInfoHint));
	RequeryAddrInfoHint.ai_family = AF_UNSPEC;
	RequeryAddrInfoHint.ai_protocol = pHintsCast->ai_protocol;
	RequeryAddrInfoHint.ai_socktype = pHintsCast->ai_socktype;
	RequeryAddrInfoHint.ai_flags = AI_NUMERICHOST;

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
			|| pHintsCast->ai_socktype == SOCK_DGRAM)
		&& (pHintsCast->ai_flags & (AI_PASSIVE | AI_NUMERICHOST) == 0)
		&& orig_fpWs2_32_GetAddrInfoW(pNodeName, pServiceName, &RequeryAddrInfoHint, &RequeryAddrInfo) == WSAHOST_NOT_FOUND
		&& *ppResultCast != NULL
		)) goto out_as_is;

	if (g_pPxchConfig->dwWillForceResolveByHostsFile && ResolveByHostsFile(NULL, pNodeName)) goto out_as_is;

	SetHostType(HOSTNAME, HostPort);
	HostPort.HostnamePort.wPort = ((PXCH_IP_PORT*)(*ppResultCast)->ai_addr)->CommonHeader.wPort;
	StringCchCopyW(&HostPort.HostnamePort.szValue, _countof(HostPort.HostnamePort.szValue), pNodeName);

	Hostname = HostPort;
	Hostname.HostnamePort.wPort = 0;

	bWillProxy = WillProxyByRule(&bMatchedHostnameRule, NULL, NULL, NULL, &HostPort, FALSE);

	if (bMatchedHostnameRule || g_pPxchConfig->dwWillUseFakeIpWhenHostnameNotMatched) {
		IPC_MSGBUF chMessageBuf;
		PXCH_UINT32 cbMessageSize;
		IPC_MSGBUF chRespMessageBuf;
		PXCH_UINT32 cbRespMessageSize;
		PXCH_IP_ADDRESS Ips[MAX_ARRAY_IP_NUM];
		PXCH_UINT32 dwIpNum;
		PXCH_IP_ADDRESS FakeIps[2];
		ADDRINFOW* NewAddrInfoWResult;
		BOOL Ipv4Only;

		AddrInfoToIps(&dwIpNum, Ips, *ppResultCast, TRUE);

		if ((dwLastError = HostnameAndIpsToMessage(chMessageBuf, &cbMessageSize, GetCurrentProcessId(), &Hostname, g_pPxchConfig->dwWillMapResolvedIpToHost, dwIpNum, Ips, bWillProxy)) != NO_ERROR) goto err;

		if ((dwLastError = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, &cbRespMessageSize)) != NO_ERROR) goto err;

		if ((dwLastError = MessageToHostnameAndIps(NULL, NULL, NULL, NULL /*Must be 2*/, FakeIps, NULL, chRespMessageBuf, cbRespMessageSize)) != NO_ERROR) goto err;

		HostnameAndIpsToAddrInfo(&NewAddrInfoWResult, &Hostname, 2, FakeIps, !!(pHintsCast->ai_flags & AI_CANONNAME), (*ppResultCast)->ai_socktype, (*ppResultCast)->ai_protocol);
		iWSALastError = NO_ERROR;
		dwLastError = NO_ERROR;
		iResult = 0;

		orig_fpWs2_32_FreeAddrInfoW(*ppResultCast);
		*ppResultCast = NewAddrInfoWResult;
	}

out:
out_as_is:
	WSASetLastError(iWSALastError);
	SetLastError(dwLastError);
	return iResult;

err:
	orig_fpWs2_32_FreeAddrInfoW(*ppResultCast);
	WSASetLastError(WSAENOMORE);
	SetLastError(dwLastError);
	return SOCKET_ERROR;
}

// Hook GetAddrInfoExA

PROXY_FUNC2(Ws2_32, GetAddrInfoExA)
{
	FUNCIPCLOGI(L"Ws2_32.dll GetAddrInfoExA() called");

	return orig_fpWs2_32_GetAddrInfoExA(pName, pServiceName, dwNameSpace, lpNspId, hints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpHandle);
}

// Hook GetAddrInfoExW

PROXY_FUNC2(Ws2_32, GetAddrInfoExW)
{
	FUNCIPCLOGI(L"Ws2_32.dll GetAddrInfoExW() called");
	
	return orig_fpWs2_32_GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, hints, ppResult, timeout, lpOverlapped, lpCompletionRoutine, lpHandle);
}

// Hook freeaddrinfo

PROXY_FUNC2(Ws2_32, freeaddrinfo)
{
	FUNCIPCLOGI(L"Ws2_32.dll freeaddrinfo() called");

	orig_fpWs2_32_freeaddrinfo(pAddrInfo);
}

// Hook FreeAddrInfoW

PROXY_FUNC2(Ws2_32, FreeAddrInfoW)
{
	FUNCIPCLOGI(L"Ws2_32.dll FreeAddrInfoW() called");
	
	orig_fpWs2_32_FreeAddrInfoW(pAddrInfo);
}

// Hook FreeAddrInfoEx

PROXY_FUNC2(Ws2_32, FreeAddrInfoEx)
{
	FUNCIPCLOGI(L"Ws2_32.dll FreeAddrInfoEx() called");

	orig_fpWs2_32_FreeAddrInfoEx(pAddrInfoEx);
}


// Hook FreeAddrInfoW

PROXY_FUNC2(Ws2_32, FreeAddrInfoExW)
{
	FUNCIPCLOGI(L"Ws2_32.dll FreeAddrInfoExW() called");

	orig_fpWs2_32_FreeAddrInfoExW(pAddrInfoEx);
}


// Hook getnameinfo

PROXY_FUNC2(Ws2_32, getnameinfo)
{
	FUNCIPCLOGI(L"Ws2_32.dll getnameinfo() called");

	return orig_fpWs2_32_getnameinfo(pSockaddr, SockaddrLength, pNodeBuffer, NodeBufferSize, pServiceBuffer, ServiceBufferSize, Flags);
}

// Hook GetNameInfoW

PROXY_FUNC2(Ws2_32, GetNameInfoW)
{
	FUNCIPCLOGI(L"Ws2_32.dll GetNameInfoW() called");

	return orig_fpWs2_32_GetNameInfoW(pSockaddr, SockaddrLength, pNodeBuffer, NodeBufferSize, pServiceBuffer, ServiceBufferSize, Flags);
}