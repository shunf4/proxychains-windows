#define PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#include "includes_win32.h"
#include "common_win32.h"
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Mswsock.h>
#include <strsafe.h>
#include "hookdll_win32.h"
#include "hookdll_interior_win32.h"
#include "log_generic.h"
#include <MinHook.h>

#include "proxy_core.h"

#ifndef __CYGWIN__
#pragma comment(lib, "Ws2_32.lib")
#endif

static PXCH_PROXY_DIRECT_DATA g_proxyDirect;
static WCHAR g_HostPrintBuf[100];

typedef struct _PXCH_WS2_32_TEMP_DATA {
	DWORD iConnectLastError;
	DWORD iConnectWSALastError;
	int iConnectReturn;
} PXCH_WS2_32_TEMP_DATA;

typedef struct _PXCH_MSWSOCK_TEMP_DATA {
	DWORD iConnectLastError;
	DWORD iConnectWSALastError;
	BOOL bConnectReturn;
} PXCH_MSWSOCK_TEMP_DATA;

static const WCHAR* FormatHostPortToStr(const void* pHostPort, int iAddrLen)
{
	DWORD dwLen;
	dwLen = _countof(g_HostPrintBuf);
	g_HostPrintBuf[0] = L'\0';

	if (HostIsType(HOSTNAME, *(PXCH_HOST*)pHostPort)) {
		StringCchPrintfW(g_HostPrintBuf, dwLen, L"%ls%hu", ((PXCH_HOSTNAME*)pHostPort)->szValue, ntohs(((PXCH_HOSTNAME*)pHostPort)->wPort));
	} else {
		WSAAddressToStringW((struct sockaddr*)(pHostPort), iAddrLen, NULL, g_HostPrintBuf, &dwLen);
	}
	return g_HostPrintBuf;
}

static BOOL WillProxyByRule(const PXCH_HOST_PORT* pHostPort, BOOL bDefault)
{
	unsigned int i;
	PXCH_RULE* pRule;

	for (i = 0; i < g_pPxchConfig->dwRuleNum; i++) {
		pRule = &PXCHCONFIG_RULE_ARR(g_pPxchConfig)[i];
		if (HostIsType(IPV4, *pHostPort) && RuleIsType(IP_CIDR, *pRule)) {
			const struct sockaddr_in* pIpv4 = (const struct sockaddr_in*)pHostPort;
			const struct sockaddr_in* pRuleIpv4 = (const struct sockaddr_in*) &pRule->HostPort;

			// long is always 32-bit
			PXCH_UINT32 dwMask = htonl(~(((PXCH_UINT64)1 << (32 - pRule->dwCidrPrefixLength)) - 1));
			
			if ((pIpv4->sin_addr.s_addr & dwMask) == (pRuleIpv4->sin_addr.s_addr & dwMask)) {
				// Match
				return (BOOL)pRule->iWillProxy;
			}
		}
	}

	return bDefault;
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

	bWillProxy = WillProxyByRule(pHostPort, FALSE);
	
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

	bWillProxy = WillProxyByRule(pHostPort, FALSE);
	
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

