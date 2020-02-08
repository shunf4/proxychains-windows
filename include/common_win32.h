#pragma once

#include "defines_win32.h"
#include "common_generic.h"

#ifdef PXCH_INCLUDE_WSOCK_UTILS
#include <WinSock2.h>
#include <Ws2Tcpip.h>
#endif

#define MAX_ERROR_MESSAGE_BUFSIZE 256
#define MAX_FWPRINTF_BUFSIZE 256

extern wchar_t szErrorMessage[MAX_ERROR_MESSAGE_BUFSIZE];

PWCHAR FormatErrorToStr(DWORD dwError);
void StdWprintf(DWORD dwStdHandle, const WCHAR* fmt, ...);
void StdVwprintf(DWORD dwStdHandle, const WCHAR* fmt, va_list args);
void StdFlush(DWORD dwStdHandle);

#ifdef PXCH_INCLUDE_WSOCK_UTILS
typedef struct _PXCH_ADDRINFOW {
	ADDRINFOW AddrInfoW;
	PXCH_HOSTNAME Hostname;
	PXCH_IP_ADDRESS Ip;
} PXCH_ADDRINFOW;

void HostentToHostnameAndIps(PXCH_HOSTNAME* pHostname, PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, const struct hostent* pHostent);
void HostnameAndIpsToHostent(struct hostent* pHostent, void* pTlsBase, const PXCH_HOSTNAME* pHostname, PXCH_UINT32 dwIpNum, const PXCH_IP_ADDRESS* Ips);
void AddrInfoToIps(PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, const void* pAddrInfo, BOOL bIsW);
void HostnameAndIpsToAddrInfo(ADDRINFOW** ppAddrInfoW, const PXCH_HOSTNAME* pHostname, PXCH_UINT32 dwIpNum, const PXCH_IP_ADDRESS* Ips, BOOL bCanonName, int iSockType, int iProtocol);
#endif
