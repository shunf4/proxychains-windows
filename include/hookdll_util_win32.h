// SPDX-License-Identifier: GPL-2.0-or-later
/* hookdll_util_win32.h
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
#pragma once

#include "defines_win32.h"
#include "hookdll_util_generic.h"

PXCH_DLL_API PWCHAR FormatErrorToStr(DWORD dwError);
PXCH_DLL_API void StdWprintf(DWORD dwStdHandle, const WCHAR* fmt, ...);
PXCH_DLL_API void StdVwprintf(DWORD dwStdHandle, const WCHAR* fmt, va_list args);
PXCH_DLL_API void StdFlush(DWORD dwStdHandle);

DWORD IpcClientRegisterChildProcessAndBackupChildData();
PXCH_UINT32 RestoreChildDataIfNecessary();

DWORD InjectTargetProcess(const PROCESS_INFORMATION* pPi, DWORD dwCreationFlags);

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
	char HostnameBuf[PXCH_MAX_HOSTNAME_BUFSIZE];
	PXCH_IP_PORT IpPort;
} PXCH_ADDRINFOA;

void HostentToHostnameAndIps(PXCH_HOSTNAME* pHostname, PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, const struct hostent* pHostent);
void HostnameAndIpsToHostent(struct hostent** ppHostent, void* pTlsBase, const PXCH_HOSTNAME* pHostname, PXCH_UINT32 dwIpNum, const PXCH_IP_ADDRESS* Ips);
void AddrInfoToIps(PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, const void* pAddrInfo, BOOL bIsW);
void HostnameAndIpPortsToAddrInfo_WillAllocate(ADDRINFOW** ppAddrInfoW, const PXCH_HOSTNAME* pHostname, PXCH_UINT32 dwIpNum, const PXCH_IP_PORT* IpPorts, BOOL bCanonName, int iSockType, int iProtocol);
#endif