#pragma once

#include "hookdll_interior_generic.h"

DWORD IpcClientRegisterChildProcess();
PXCH_UINT32 RestoreChildData();

DWORD InjectTargetProcess(const PROCESS_INFORMATION* pPi);

void Win32HookWs2_32(void);
void CygwinHook(void);

#ifdef PXCH_INCLUDE_WINSOCK_UTIL
#include <WinSock2.h>
#include <Ws2Tcpip.h>

typedef struct _PXCH_ADDRINFOW {
	ADDRINFOW AddrInfoW;
	PXCH_HOSTNAME Hostname;
	PXCH_IP_PORT IpPort;
} PXCH_ADDRINFOW;

typedef struct _PXCH_ADDRINFOA {
	ADDRINFOA AddrInfoA;
	char HostnameBuf[MAX_HOSTNAME_BUFSIZE];
	PXCH_IP_PORT IpPort;
} PXCH_ADDRINFOA;

void HostentToHostnameAndIps(PXCH_HOSTNAME* pHostname, PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, const struct hostent* pHostent);
void HostnameAndIpsToHostent(struct hostent** ppHostent, void* pTlsBase, const PXCH_HOSTNAME* pHostname, PXCH_UINT32 dwIpNum, const PXCH_IP_ADDRESS* Ips);
void AddrInfoToIps(PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, const void* pAddrInfo, BOOL bIsW);
void HostnameAndIpPortsToAddrInfo_WillAllocate(ADDRINFOW** ppAddrInfoW, const PXCH_HOSTNAME* pHostname, PXCH_UINT32 dwIpNum, const PXCH_IP_PORT* IpPorts, BOOL bCanonName, int iSockType, int iProtocol);
#endif