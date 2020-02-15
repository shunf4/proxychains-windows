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
#include "hookdll_interior_win32.h"
#include "log_win32.h"
#include <MinHook.h>

#include "hookdll_win32.h"

void Win32HookWs2_32(void)
{
	HMODULE hWs2_32;
	LPVOID pWs2_32_WSAStartup = NULL;
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
	LPVOID pWs2_32_FreeAddrInfoEx = NULL;
	LPVOID pWs2_32_FreeAddrInfoExW = NULL;
	LPVOID pWs2_32_getnameinfo = NULL;
	LPVOID pWs2_32_GetNameInfoW = NULL;

	LoadLibraryW(L"ws2_32.dll");

	if ((hWs2_32 = GetModuleHandleW(L"ws2_32.dll"))) {
		pWs2_32_WSAStartup = GetProcAddress(hWs2_32, "WSAStartup");
		pWs2_32_WSAConnect = GetProcAddress(hWs2_32, "WSAConnect");
		pWs2_32_connect = GetProcAddress(hWs2_32, "connect");
		pWs2_32_gethostbyname = GetProcAddress(hWs2_32, "gethostbyname");
		pWs2_32_gethostbyaddr = GetProcAddress(hWs2_32, "gethostbyaddr");
		pWs2_32_getaddrinfo = GetProcAddress(hWs2_32, "getaddrinfo");
		pWs2_32_GetAddrInfoW = GetProcAddress(hWs2_32, "GetAddrInfoW");
		pWs2_32_GetAddrInfoExA = GetProcAddress(hWs2_32, "GetAddrInfoExA");
		pWs2_32_GetAddrInfoExW = GetProcAddress(hWs2_32, "GetAddrInfoExW");
		pWs2_32_freeaddrinfo = GetProcAddress(hWs2_32, "freeaddrinfo");
		pWs2_32_FreeAddrInfoW = GetProcAddress(hWs2_32, "FreeAddrInfoW");
		pWs2_32_FreeAddrInfoEx = GetProcAddress(hWs2_32, "FreeAddrInfoEx");
		pWs2_32_FreeAddrInfoExW = GetProcAddress(hWs2_32, "FreeAddrInfoExW");
		pWs2_32_getnameinfo = GetProcAddress(hWs2_32, "getnameinfo");
		pWs2_32_GetNameInfoW = GetProcAddress(hWs2_32, "GetNameInfoW");
	}

	// Another hook on ConnectEx() will take effect at WSAStartup()
	CREATE_HOOK3_IFNOTNULL(Ws2_32, WSAStartup, pWs2_32_WSAStartup);
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
	CREATE_HOOK3_IFNOTNULL(Ws2_32, FreeAddrInfoEx, pWs2_32_FreeAddrInfoEx);
	CREATE_HOOK3_IFNOTNULL(Ws2_32, FreeAddrInfoExW, pWs2_32_FreeAddrInfoExW);
	CREATE_HOOK3_IFNOTNULL(Ws2_32, getnameinfo, pWs2_32_getnameinfo);
	CREATE_HOOK3_IFNOTNULL(Ws2_32, GetNameInfoW, pWs2_32_GetNameInfoW);

	if (orig_fpWs2_32_FreeAddrInfoW == NULL) orig_fpWs2_32_FreeAddrInfoW = orig_fpWs2_32_freeaddrinfo;
	if (orig_fpWs2_32_FreeAddrInfoExW == NULL) orig_fpWs2_32_FreeAddrInfoExW = orig_fpWs2_32_FreeAddrInfoEx;
}

void CygwinHook(void)
{
	HMODULE hCygwin1;
	LPVOID pCygwin1_connect = NULL;

	LoadLibraryW(L"cygwin1.dll");

	if ((hCygwin1 = GetModuleHandleW(L"cygwin1.dll"))) { pCygwin1_connect = GetProcAddress(hCygwin1, "connect"); }

	CREATE_HOOK3_IFNOTNULL(Cygwin1, connect, pCygwin1_connect);
}
