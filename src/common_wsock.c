#define PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#define PXCH_INCLUDE_WSOCK_UTILS
#include "includes_win32.h"
#include "defines_win32.h"
#include "common_win32.h"
#include <stdlib.h>
#include <WinSock2.h>
#include <Ws2Tcpip.h>
#include <wchar.h>
#include <strsafe.h>
	
static WCHAR g_HostPrintBuf[100];

const PXCH_UINT32 g_dwW32HostentSize = sizeof(struct hostent);

const wchar_t* FormatHostPortToStr(const void* pHostPort, int iAddrLen)
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

void IndexToIp(const PROXYCHAINS_CONFIG* pPxchConfig, PXCH_IP_ADDRESS* pIp, PXCH_UINT32 iIndex)
{
	PXCH_HOST* pHost = (PXCH_HOST*)pIp;
	ZeroMemory(pIp, sizeof(PXCH_IP_ADDRESS));
	if (HostIsType(IPV4, *pHost)) {
		struct sockaddr_in* pIpv4 = (struct sockaddr_in*)pIp;
		pIpv4->sin_family = PXCH_HOST_TYPE_IPV4;
		PXCH_UINT32 dwMaskInvert;
		PXCH_UINT32 dwToShift = pPxchConfig->dwFakeIpv4PrefixLength > 32 ? 0 : 32 - pPxchConfig->dwFakeIpv4PrefixLength;

		pIpv4->sin_addr = ((struct sockaddr_in*) & pPxchConfig->FakeIpv4Range)->sin_addr;
		dwMaskInvert = htonl((PXCH_UINT32)((((PXCH_UINT64)1) << dwToShift) - 1));
		pIpv4->sin_addr.s_addr &= ~dwMaskInvert;
		pIpv4->sin_addr.s_addr |= (htonl(iIndex) & dwMaskInvert);
		goto out_succ;
	}

	if (HostIsType(IPV6, *pHost)) {
		struct sockaddr_in6* pIpv6 = (struct sockaddr_in6*)pIp;
		pIpv6->sin6_family = PXCH_HOST_TYPE_IPV6;
		struct {
			PXCH_UINT64 First64;
			PXCH_UINT64 Last64;
		} MaskInvert, * pIpv6AddrInQwords;

		PXCH_UINT32 dwToShift = pPxchConfig->dwFakeIpv6PrefixLength > 128 ? 0 : 128 - pPxchConfig->dwFakeIpv6PrefixLength;
		PXCH_UINT32 dwShift1 = dwToShift >= 64 ? 64 : dwToShift;
		PXCH_UINT32 dwShift2 = dwToShift >= 64 ? (dwToShift - 64) : 0;

		MaskInvert.Last64 = dwShift1 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift1) - 1);
		MaskInvert.First64 = dwShift2 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift2) - 1);

		if (LITTLEENDIAN) {
			MaskInvert.Last64 = _byteswap_uint64(MaskInvert.Last64);
			MaskInvert.First64 = _byteswap_uint64(MaskInvert.First64);
		}


		pIpv6->sin6_addr = ((struct sockaddr_in6*) & pPxchConfig->FakeIpv6Range)->sin6_addr;
		pIpv6AddrInQwords = (void*)&pIpv6->sin6_addr;
		pIpv6AddrInQwords->First64 &= ~MaskInvert.First64;
		pIpv6AddrInQwords->Last64 &= ~MaskInvert.Last64;
		pIpv6AddrInQwords->Last64 |= (htonl(iIndex) & MaskInvert.Last64);
		goto out_succ;
	}
	return;

out_succ:
	;
}

void IpToIndex(const PROXYCHAINS_CONFIG* pPxchConfig, PXCH_UINT32* piIndex, const PXCH_IP_ADDRESS* pIp)
{
	PXCH_HOST* pHost = (PXCH_HOST*)pIp;
	if (HostIsType(IPV4, *pHost)) {
		struct sockaddr_in* pIpv4 = (struct sockaddr_in*)pIp;
		PXCH_UINT32 dwMaskInvert;
		PXCH_UINT32 dwToShift = pPxchConfig->dwFakeIpv4PrefixLength > 32 ? 0 : 32 - pPxchConfig->dwFakeIpv4PrefixLength;

		dwMaskInvert = htonl((PXCH_UINT32)((((PXCH_UINT64)1) << dwToShift) - 1));
		*piIndex = pIpv4->sin_addr.s_addr & dwMaskInvert;
		goto out_succ;
	}

	if (HostIsType(IPV6, *pHost)) {
		struct sockaddr_in6* pIpv6 = (struct sockaddr_in6*)pIp;
		struct {
			PXCH_UINT64 First64;
			PXCH_UINT64 Last64;
		} MaskInvert, * pIpv6AddrInQwords;

		PXCH_UINT32 dwToShift = pPxchConfig->dwFakeIpv6PrefixLength > 128 ? 0 : 128 - pPxchConfig->dwFakeIpv6PrefixLength;
		PXCH_UINT32 dwShift1 = dwToShift >= 64 ? 64 : dwToShift;
		PXCH_UINT32 dwShift2 = dwToShift >= 64 ? (dwToShift - 64) : 0;

		MaskInvert.Last64 = dwShift1 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift1) - 1);
		MaskInvert.First64 = dwShift2 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift2) - 1);

		if (LITTLEENDIAN) {
			MaskInvert.Last64 = _byteswap_uint64(MaskInvert.Last64);
			MaskInvert.First64 = _byteswap_uint64(MaskInvert.First64);
		}

		pIpv6AddrInQwords = (void*)&pIpv6->sin6_addr;

		*piIndex = (PXCH_UINT32)(pIpv6AddrInQwords->Last64 & MaskInvert.Last64);
		goto out_succ;
	}

	*piIndex = -1;
	return;

out_succ:
	;
}

void HostentToHostnameAndIps(PXCH_HOSTNAME* pHostname, PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, const struct hostent* pHostent)
{
	PXCH_UINT32 i;

	pHostname->wTag = PXCH_HOST_TYPE_HOSTNAME;
	pHostname->wPort = 0;
	StringCchPrintfW(pHostname->szValue, _countof(pHostname->szValue), L"%S", pHostent->h_name);

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
			Ips[i] = *(PXCH_IP_ADDRESS*)pAddrInfoW->ai_addr;
		}
	} else {
		for (i = 0; pAddrInfoA && i < MAX_ARRAY_IP_NUM; pAddrInfoA = pAddrInfoA->ai_next, i++) {
			Ips[i] = *(PXCH_IP_ADDRESS*)pAddrInfoA->ai_addr;
		}
	}

	*pdwIpNum = i;
}

void HostnameAndIpsToAddrInfo(ADDRINFOW** ppAddrInfoW, const PXCH_HOSTNAME* pHostname, PXCH_UINT32 dwIpNum, const PXCH_IP_ADDRESS* Ips, BOOL bCanonName, int iSockType, int iProtocol)
{
	ADDRINFOW** ppTempAddrInfoW;
	ADDRINFOW* pAddrInfoW;
	PXCH_ADDRINFOW* pPxchAddrInfoW;
	PXCH_UINT32 i;

	ppTempAddrInfoW = ppAddrInfoW;

	*ppAddrInfoW = NULL;

	for (i = 0; i < dwIpNum; i++) {
		*ppTempAddrInfoW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PXCH_ADDRINFOW));
		pAddrInfoW = *ppTempAddrInfoW;
		pPxchAddrInfoW = (PXCH_ADDRINFOW*)*ppTempAddrInfoW;

		pPxchAddrInfoW->Ip = Ips[i];
		pPxchAddrInfoW->Hostname = *pHostname;

		pAddrInfoW->ai_addr = (struct sockaddr*)&pPxchAddrInfoW->Ip;
		pAddrInfoW->ai_addrlen = HostIsType(IPV4, *(const PXCH_HOST*)&Ips[i]) ? sizeof(struct sockaddr_in) : HostIsType(IPV6, *(const PXCH_HOST*)&Ips[i]) ? sizeof(struct sockaddr_in6) : 0;
		pAddrInfoW->ai_canonname = bCanonName ? pPxchAddrInfoW->Hostname.szValue : NULL;
		pAddrInfoW->ai_family = Ips[i].Sockaddr.sa_family;
		pAddrInfoW->ai_flags = 0;
		pAddrInfoW->ai_protocol = iProtocol;
		pAddrInfoW->ai_socktype = iSockType;
		pAddrInfoW->ai_next = NULL;
		ppTempAddrInfoW = &pAddrInfoW->ai_next;
	}
}