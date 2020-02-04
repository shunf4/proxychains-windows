#define PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#include "includes_win32.h"
#include "common_win32.h"
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <strsafe.h>
#include "hookdll_win32.h"
#include "proxy_core.h"
#include "log_generic.h"

#ifndef __CYGWIN__
#pragma comment(lib, "Ws2_32.lib")
#endif

static PXCH_PROXY_DIRECT_DATA g_proxyDirect;
static WCHAR g_HostPrintBuf[100];

static const WCHAR* FormatHostPortToStr(const void* pHostPort, int iSockLen)
{
	DWORD dwLen;
	dwLen = _countof(g_HostPrintBuf);
	g_HostPrintBuf[0] = L'\0';

	if (HostIsType(HOSTNAME, *(PXCH_HOST*)pHostPort)) {
		StringCchPrintfW(g_HostPrintBuf, dwLen, L"%ls%hu", ((PXCH_HOSTNAME*)pHostPort)->szValue, ntohs(((PXCH_HOSTNAME*)pHostPort)->wPort));
	} else {
		WSAAddressToStringW((struct sockaddr*)(pHostPort), iSockLen, NULL, g_HostPrintBuf, &dwLen);
	}
	return g_HostPrintBuf;
}

int Ws2_32BlockConnect(PXCH_UINT_PTR s, const void* pAddr, int iAddrLen)
{
	int iReturn;
	int iWSALastError;
	int iLastError;
	fd_set wfds;

	iReturn = orig_fpWs2_32_connect(s, pAddr, iAddrLen);
	iWSALastError = WSAGetLastError();
	iLastError = GetLastError();
	if (iReturn) {
		if (iWSALastError == WSAEWOULDBLOCK) {
			FUNCIPCLOGD(L"connect(): this socket is nonblocking and it didn't finish instantly.");
		}
		else goto err_connect;
	}

	FD_ZERO(&wfds);
	FD_SET(s, &wfds);
	iReturn = select(-1, NULL, &wfds, NULL, NULL);
	iWSALastError = WSAGetLastError();
	iLastError = GetLastError();
	if (iReturn == SOCKET_ERROR) goto err_select;
	if (iReturn != 1 || !FD_ISSET(s, &wfds)) goto err_select_unexpected;

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

int Ws2_32LoopSend(PXCH_UINT_PTR s, const char* SendBuf, int iLength)
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

int Ws2_32LoopRecv(PXCH_UINT_PTR s, char* RecvBuf, int iLength)
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

PXCHDLL_API int Ws2_32DirectConnect(PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen)
{
	if (HostIsType(HOSTNAME, *pHostPort) || HostIsType(INVALID, *pHostPort)) {
		FUNCIPCLOGW(L"Error connecting directly: address is hostname or invalid (%#06hx).", *(const PXCH_UINT16*)pHostPort);
		WSASetLastError(WSAEAFNOSUPPORT);
		return SOCKET_ERROR;
	}
	FUNCIPCLOGI(L"Ws2_32DirectConnect(%ls)", FormatHostPortToStr(pHostPort, iAddrLen));
	return Ws2_32BlockConnect(s, pHostPort, iAddrLen);
}

PXCHDLL_API int Ws2_32Socks5Connect(PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen)
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

	// Handshake
	if ((iResult = Ws2_32LoopSend(s, "\05\01\00", 3)) == SOCKET_ERROR) goto err_general;
	if ((iResult = Ws2_32LoopRecv(s, RecvBuf, 2)) == SOCKET_ERROR) goto err_general;
	if (RecvBuf[1] != '\00') goto err_data_invalid_1;

	if (HostIsType(IPV4, *pHostPort)) {
		SockAddrIpv4 = (const struct sockaddr_in*)pHostPort;
		
		// Connect
		CopyMemory(SendBuf, "\05\01\00\x01\xFF\xFF\xFF\xFF\xEE\xEE", 10);
		CopyMemory(SendBuf + 4, &SockAddrIpv4->sin_addr, 4);
		CopyMemory(SendBuf + 8, &SockAddrIpv4->sin_port, 2);
		if ((iResult = Ws2_32LoopSend(s, SendBuf, 10)) == SOCKET_ERROR) goto err_general;
		if ((iResult = Ws2_32LoopRecv(s, RecvBuf, 10)) == SOCKET_ERROR) goto err_general;
		if (RecvBuf[1] != '\00' || RecvBuf[3] != '\01') goto err_data_invalid_2;
	} else goto err_not_supported;

	return 0;

err_not_supported:
	FUNCIPCLOGW(L"Error connecting through Socks5: addresses other than Ipv4 not implemented.");
	iResult = SOCKET_ERROR;
	SetLastError(ERROR_NOT_SUPPORTED);
	WSASetLastError(WSAEAFNOSUPPORT);
	goto err_general;

err_data_invalid_1:
	FUNCIPCLOGW(L"Socks5 data format invalid: server disallows NoAuth");
	goto err_general;

err_data_invalid_2:
	// TODO: Fix later
	FUNCIPCLOGW(L"Socks5 data format invalid: server disallows this connection");
	goto err_general;

err_general:
	shutdown(s, SD_BOTH);
	return iResult;
}

PXCHDLL_API int Ws2_32Socks5Handshake(PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */)
{
	WSASetLastError(NO_ERROR);
	return 0;
}

int Ws2_32GenericConnectTo(PXCH_UINT_PTR s, PPXCH_CHAIN pChain, const PXCH_HOST_PORT* pHostPort, int iAddrLen)
{
	if (*pChain == NULL) {
		SetProxyType(DIRECT, g_proxyDirect);
		g_proxyDirect.Ws2_32FpConnect = &Ws2_32DirectConnect;
		g_proxyDirect.Ws2_32FpHandshake = NULL;

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

	iReturn = pProxy->CommonHeader.Ws2_32FpConnect(s, pProxy, pHostPort, iAddrLen);
	return iReturn;
}

int Ws2_32GenericTunnelTo(PXCH_UINT_PTR s, PPXCH_CHAIN pChain, PXCH_PROXY_DATA* pProxy)
{
	int iLastError;
	int iReturn;
	PXCH_CHAIN_NODE* pNewNode;

	FUNCIPCLOGI(L"Ws2_32GenericConnectTo(%ls)", FormatHostPortToStr(&pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iSockLen));
	iReturn = Ws2_32GenericConnectTo(s, pChain, &pProxy->CommonHeader.HostPort, pProxy->CommonHeader.iSockLen);
	iLastError = WSAGetLastError();
	if (iReturn) goto err_return;

	pNewNode = HeapAlloc(GetProcessHeap(), 0, sizeof(PXCH_CHAIN_NODE));
	pNewNode->pProxy = pProxy;

	CDL_APPEND((*pChain), pNewNode);

	iReturn = pNewNode->pProxy->CommonHeader.Ws2_32FpHandshake(s, pProxy);
	iLastError = WSAGetLastError();

err_return:
	WSASetLastError(iLastError);
	return iReturn;
}

PROXY_FUNC2(Ws2_32, connect)
{
	// SOCKET real_s = s;
	const PXCH_HOST_PORT* pHostPort = name;
	unsigned int i;
	int iReturn = 0;
	int iLastError;
	int iWSALastError;
	PXCH_RULE* pRule;
	BOOL bWillProxy;
	PXCH_CHAIN Chain = NULL;
	PXCH_CHAIN_NODE* ChainNode = NULL;

	RestoreChildData();

	bWillProxy = FALSE;
	for (i = 0; i < g_pPxchConfig->dwRuleNum; i++) {
		pRule = &PXCHCONFIG_RULE_ARR(g_pPxchConfig)[i];
		if (HostIsType(IPV4, *pHostPort) && RuleIsType(IP_CIDR, *pRule)) {
			const struct sockaddr_in* pIpv4 = (const struct sockaddr_in*)pHostPort;
			const struct sockaddr_in* pRuleIpv4 = (const struct sockaddr_in*) &pRule->HostAddress;
			PXCH_UINT32 dwMask = ~(((PXCH_UINT64)1 << (32 - pRule->dwCidrPrefixLength)) - 1);
			if ((pIpv4->sin_addr.s_addr & dwMask) == (pRuleIpv4->sin_addr.s_addr & dwMask)) {
				// Match
				bWillProxy = pRule->iWillProxy;
				break;
			}
		}
	}

	if (!bWillProxy) {
		iReturn = Ws2_32DirectConnect(s, NULL, name, namelen);
		goto record_error_end;
	}

	for (i = 0; i < g_pPxchConfig->dwProxyNum; i++) {
		if ((iReturn = Ws2_32GenericTunnelTo(s, &Chain, &PXCHCONFIG_PROXY_ARR(g_pPxchConfig)[i])) == SOCKET_ERROR) goto record_error_end;
	}
	if ((iReturn = Ws2_32GenericConnectTo(s, &Chain, name, namelen)) == SOCKET_ERROR) goto record_error_end;

	return NO_ERROR;

record_error_end:
	iWSALastError = WSAGetLastError();
	iLastError = GetLastError();

	
	FUNCIPCLOGI(L"ws2_32.dll connect(%d, %ls, %d) proxied: %d", s, FormatHostPortToStr(name, namelen), namelen, bWillProxy);
	if (bWillProxy) {
		CDL_FOREACH(Chain, ChainNode) {
			FUNCIPCLOGI(L"<> %ls", FormatHostPortToStr(&ChainNode->pProxy->CommonHeader.HostPort, ChainNode->pProxy->CommonHeader.iSockLen));
		}
	}

	// TODO: free
	FUNCIPCLOGI(L"ws2_32.dll connect() ret: %d, wsa last error: %ls", iReturn, FormatErrorToStr(iWSALastError));
	WSASetLastError(iWSALastError);
	SetLastError(iLastError);
	return iReturn;
}
