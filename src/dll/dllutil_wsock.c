#define PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#define PXCH_INCLUDE_WINSOCK_UTIL
#include "includes_win32.h"
#include "defines_win32.h"
#include "hookdll_interior_win32.h"
#include <stdlib.h>
#include <wchar.h>
#include <strsafe.h>

#include "log_generic.h"
#include "tls_win32.h"
#include "hookdll_win32.h"
#include "ut_helpers.h"
	

PXCH_DLL_API const PXCH_UINT32 g_dwW32HostentSize = sizeof(struct hostent);

void HostentToHostnameAndIps(PXCH_HOSTNAME* pHostname, PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, const struct hostent* pHostent)
{
	PXCH_UINT32 i;

	pHostname->wTag = PXCH_HOST_TYPE_HOSTNAME;
	pHostname->wPort = 0;
	StringCchPrintfW(pHostname->szValue, _countof(pHostname->szValue), WPRS, pHostent->h_name);

	ZeroMemory(Ips, sizeof(PXCH_IP_ADDRESS) * MAX_ARRAY_IP_NUM);

	if (pHostent->h_length != sizeof(PXCH_UINT32)) goto err_not_supported;

	for (i = 0; pHostent->h_addr_list[i]; i++) {
		SetHostType(IPV4, *(PXCH_HOST*)&Ips[i]);
		((struct sockaddr_in*)&(Ips[i]))->sin_addr.s_addr = *(PXCH_UINT32*)pHostent->h_addr_list[i];
	}

	*pdwIpNum = i;

err_not_supported:
	*pdwIpNum = 0;
}

void HostnameAndIpsToHostent(struct hostent* pHostent, void* pTlsBase, const PXCH_HOSTNAME* pHostname, PXCH_UINT32 dwIpNum, const PXCH_IP_ADDRESS* Ips)
{
	PXCH_UINT32 i;
	PXCH_UINT32 j;
	PXCH_UINT32** ppIp;

	pHostent->h_length = sizeof(PXCH_UINT32);
	pHostent->h_addrtype = AF_INET;

	pHostent->h_addr_list = PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_AS_PPCHAR_BY_BASE(pTlsBase);
	ppIp = PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_BY_BASE(pTlsBase);
	pHostent->h_aliases = (char**)PXCH_TLS_PTR_W32HOSTENT_ALIAS_PTR_LIST_BY_BASE(pTlsBase);
	pHostent->h_name = *PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF_BY_BASE(pTlsBase);

	ZeroMemory(ppIp, sizeof(PXCH_UINT32 * [PXCH_TLS_W32HOSTENT_IP_NUM]));
	for (i = 0, j = 0; i < dwIpNum; i++) {
		if (HostIsType(IPV4, *(PXCH_HOST*)&Ips[i])) {
			ppIp[j] = &PXCH_TLS_PTR_W32HOSTENT_IP_BUF_BY_BASE(pTlsBase)[j];
			CopyMemory(&PXCH_TLS_PTR_W32HOSTENT_IP_BUF_BY_BASE(pTlsBase)[j], &((struct sockaddr_in*)&Ips[i])->sin_addr, sizeof(PXCH_UINT32));
			j++;
			if (j >= MAX_ARRAY_IP_NUM) break;
		}
	}

	ZeroMemory(pHostent->h_aliases, sizeof(char* [PXCH_TLS_W32HOSTENT_ALIAS_NUM]));

	StringCchPrintfA(*PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF_BY_BASE(pTlsBase), _countof(*PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF_BY_BASE(pTlsBase)), "%ls", pHostname->szValue);
}

void AddrInfoToIps(PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, const void* pAddrInfo, BOOL bIsW)
{
	const ADDRINFOA* pAddrInfoA = pAddrInfo;
	const ADDRINFOW* pAddrInfoW = pAddrInfo;
	PXCH_UINT32 i;

	ZeroMemory(Ips, sizeof(PXCH_IP_ADDRESS) * MAX_ARRAY_IP_NUM);

	if (bIsW) {
		for (i = 0; pAddrInfoW && i < MAX_ARRAY_IP_NUM; pAddrInfoW = pAddrInfoW->ai_next, i++) {
			CopyMemory(&Ips[i], pAddrInfoW->ai_addr, pAddrInfoW->ai_addrlen);
			Ips[i].CommonHeader.wPort = 0;
		}
	} else {
		for (i = 0; pAddrInfoA && i < MAX_ARRAY_IP_NUM; pAddrInfoA = pAddrInfoA->ai_next, i++) {
			CopyMemory(&Ips[i], pAddrInfoA->ai_addr, pAddrInfoA->ai_addrlen);
			Ips[i].CommonHeader.wPort = 0;
		}
	}

	*pdwIpNum = i;
}

void HostnameAndIpsToAddrInfo_WillAllocate(ADDRINFOW** ppAddrInfoW, const PXCH_HOSTNAME* pHostname, PXCH_UINT32 dwIpNum, const PXCH_IP_ADDRESS* Ips, BOOL bCanonName, int iSockType, int iProtocol)
{
	PXCH_DO_IN_CRITICAL_SECTION_RETURN_VOID{
		ADDRINFOW * *ppTempAddrInfoW;
		ADDRINFOW* pAddrInfoW;
		PXCH_ADDRINFOW* pPxchAddrInfoW;
		PXCH_ADDRINFOW* pBuf = NULL;
		PXCH_UINT32 i;

		if (dwIpNum) {
			pBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PXCH_ADDRINFOW) * dwIpNum);
			utarray_push_back(g_arrHeapAllocatedPointers, &pBuf);
		}

		ppTempAddrInfoW = ppAddrInfoW;
		*ppAddrInfoW = NULL;

		for (i = 0; i < dwIpNum; i++) {
			*ppTempAddrInfoW = (ADDRINFOW*)&pBuf[i];
			pAddrInfoW = *ppTempAddrInfoW;
			pPxchAddrInfoW = (PXCH_ADDRINFOW*)*ppTempAddrInfoW;

			pPxchAddrInfoW->Ip = Ips[i];
			pPxchAddrInfoW->Hostname = *pHostname;

			pAddrInfoW->ai_addr = (struct sockaddr*) & pPxchAddrInfoW->Ip;
			pAddrInfoW->ai_addrlen = HostIsType(IPV4, *(const PXCH_HOST*)&Ips[i]) ? sizeof(struct sockaddr_in) : HostIsType(IPV6, *(const PXCH_HOST*)&Ips[i]) ? sizeof(struct sockaddr_in6) : 0;
			pAddrInfoW->ai_canonname = bCanonName ? pPxchAddrInfoW->Hostname.szValue : NULL;
			pAddrInfoW->ai_family = Ips[i].Sockaddr.wTag;
			pAddrInfoW->ai_flags = 0;
			pAddrInfoW->ai_protocol = iProtocol;
			pAddrInfoW->ai_socktype = iSockType;
			pAddrInfoW->ai_next = NULL;

			ppTempAddrInfoW = &pAddrInfoW->ai_next;
		}
	}
}