// SPDX-License-Identifier: GPL-2.0-or-later
/* hook_installer.c
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
#include "includes_win32.h"
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Mswsock.h>
#include "hookdll_util_win32.h"
#include "log_win32.h"
#include <MinHook.h>

#include "hookdll_win32.h"

void Win32HookWs2_32(void)
{
	HMODULE hWs2_32;
	// LPVOID pWs2_32_WSAStartup = NULL;
	LPVOID pWs2_32_WSAConnect = NULL;
	LPVOID pWs2_32_connect = NULL;
	LPVOID pWs2_32_gethostbyname = NULL;
	LPVOID pWs2_32_gethostbyaddr = NULL;
	LPVOID pWs2_32_getaddrinfo = NULL;
	LPVOID pWs2_32_GetAddrInfoW = NULL;
	LPVOID pWs2_32_GetAddrInfoExA = NULL;
	LPVOID pWs2_32_GetAddrInfoExW = NULL;
	LPVOID pWs2_32_freeaddrinfo = NULL;
	LPVOID pWs2_32_FreeAddrInfoW = NULL;
	LPVOID pWs2_32_FreeAddrInfoExA_ = NULL;
	LPVOID pWs2_32_FreeAddrInfoExW = NULL;
	LPVOID pWs2_32_getnameinfo = NULL;
	LPVOID pWs2_32_GetNameInfoW = NULL;

	LoadLibraryW(L"ws2_32.dll");

	if ((hWs2_32 = GetModuleHandleW(L"ws2_32.dll"))) {
		// orig_fpWs2_32_WSAStartup = (void*)GetProcAddress(hWs2_32, "WSAStartup");
		orig_fpWs2_32_WSAConnect = (void*)GetProcAddress(hWs2_32, "WSAConnect");
		orig_fpWs2_32_connect = (void*)GetProcAddress(hWs2_32, "connect");

		// pWs2_32_WSAStartup = orig_fpWs2_32_WSAStartup;
		pWs2_32_WSAConnect = orig_fpWs2_32_WSAConnect;
		pWs2_32_connect = orig_fpWs2_32_connect;

		orig_fpWs2_32_gethostbyname    = (void*)GetProcAddress(hWs2_32, "gethostbyname");
		orig_fpWs2_32_gethostbyaddr    = (void*)GetProcAddress(hWs2_32, "gethostbyaddr");
		orig_fpWs2_32_getaddrinfo      = (void*)GetProcAddress(hWs2_32, "getaddrinfo");
		orig_fpWs2_32_GetAddrInfoW     = (void*)GetProcAddress(hWs2_32, "GetAddrInfoW");
		orig_fpWs2_32_GetAddrInfoExA   = (void*)GetProcAddress(hWs2_32, "GetAddrInfoExA");
		orig_fpWs2_32_GetAddrInfoExW   = (void*)GetProcAddress(hWs2_32, "GetAddrInfoExW");
		orig_fpWs2_32_freeaddrinfo     = (void*)GetProcAddress(hWs2_32, "freeaddrinfo");
		orig_fpWs2_32_FreeAddrInfoW    = (void*)GetProcAddress(hWs2_32, "FreeAddrInfoW");
		orig_fpWs2_32_FreeAddrInfoExA_ = (void*)GetProcAddress(hWs2_32, "FreeAddrInfoExA");
		orig_fpWs2_32_FreeAddrInfoExW  = (void*)GetProcAddress(hWs2_32, "FreeAddrInfoExW");
		orig_fpWs2_32_getnameinfo      = (void*)GetProcAddress(hWs2_32, "getnameinfo");
		orig_fpWs2_32_GetNameInfoW     = (void*)GetProcAddress(hWs2_32, "GetNameInfoW");

		pWs2_32_gethostbyname    = orig_fpWs2_32_gethostbyname   ;
		pWs2_32_gethostbyaddr    = orig_fpWs2_32_gethostbyaddr   ;
		pWs2_32_getaddrinfo      = orig_fpWs2_32_getaddrinfo     ;
		pWs2_32_GetAddrInfoW     = orig_fpWs2_32_GetAddrInfoW    ;
		pWs2_32_GetAddrInfoExA   = orig_fpWs2_32_GetAddrInfoExA  ;
		pWs2_32_GetAddrInfoExW   = orig_fpWs2_32_GetAddrInfoExW  ;
		pWs2_32_freeaddrinfo     = orig_fpWs2_32_freeaddrinfo    ;
		pWs2_32_FreeAddrInfoW    = orig_fpWs2_32_FreeAddrInfoW   ;
		pWs2_32_FreeAddrInfoExA_ = orig_fpWs2_32_FreeAddrInfoExA_;
		pWs2_32_FreeAddrInfoExW  = orig_fpWs2_32_FreeAddrInfoExW ;
		pWs2_32_getnameinfo      = orig_fpWs2_32_getnameinfo     ;
		pWs2_32_GetNameInfoW     = orig_fpWs2_32_GetNameInfoW    ;

		// CREATE_HOOK3_IFNOTNULL(Ws2_32, WSAStartup, pWs2_32_WSAStartup);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, WSAConnect, pWs2_32_WSAConnect);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, connect, pWs2_32_connect);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, gethostbyname, pWs2_32_gethostbyname);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, gethostbyaddr, pWs2_32_gethostbyaddr);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, getaddrinfo, pWs2_32_getaddrinfo);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, GetAddrInfoW, pWs2_32_GetAddrInfoW);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, GetAddrInfoExA, pWs2_32_GetAddrInfoExA);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, GetAddrInfoExW, pWs2_32_GetAddrInfoExW);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, freeaddrinfo, pWs2_32_freeaddrinfo);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, FreeAddrInfoW, pWs2_32_FreeAddrInfoW);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, FreeAddrInfoExA_, pWs2_32_FreeAddrInfoExA_);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, FreeAddrInfoExW, pWs2_32_FreeAddrInfoExW);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, getnameinfo, pWs2_32_getnameinfo);
		CREATE_HOOK3_IFNOTNULL(Ws2_32, GetNameInfoW, pWs2_32_GetNameInfoW);

		if (orig_fpWs2_32_FreeAddrInfoW == NULL) orig_fpWs2_32_FreeAddrInfoW = orig_fpWs2_32_freeaddrinfo;
		if (orig_fpWs2_32_FreeAddrInfoExW == NULL) orig_fpWs2_32_FreeAddrInfoExW = orig_fpWs2_32_FreeAddrInfoExW;

		// Hook ConnectEx()
#ifndef __CYGWIN__
		{
			int iReturn;
			SOCKET DummySocket;
			WSADATA DummyWsaData;

			iReturn = WSAStartup(MAKEWORD(2, 2), &DummyWsaData);

			if (iReturn == 0) {
				GUID GuidConnectEx = WSAID_CONNECTEX;
				LPFN_CONNECTEX fpConnectEx = NULL;
				DWORD cb;

				DummySocket = socket(AF_INET, SOCK_STREAM, 0);
				if (DummySocket != INVALID_SOCKET) {
					if (WSAIoctl(DummySocket, SIO_GET_EXTENSION_FUNCTION_POINTER, &GuidConnectEx, sizeof(GUID), &fpConnectEx, sizeof(LPFN_CONNECTEX), &cb, NULL, NULL) == 0) {
						if (fpConnectEx) {
							CREATE_HOOK3_IFNOTNULL(Mswsock, ConnectEx, fpConnectEx);
						}
					}
					closesocket(DummySocket);
				}
			}
		}
#endif
	}
}

void CygwinHook(void)
{
	HMODULE hCygwin1;
	LPVOID pCygwin1_connect = NULL;

	LoadLibraryW(L"cygwin1.dll");

	if ((hCygwin1 = GetModuleHandleW(L"cygwin1.dll"))) { pCygwin1_connect = GetProcAddress(hCygwin1, "connect"); }

	CREATE_HOOK3_IFNOTNULL(Cygwin1, connect, pCygwin1_connect);
}
