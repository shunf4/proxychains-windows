// SPDX-License-Identifier: GPL-2.0-or-later
/* hookdll_win32.h
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
#include "hookdll_generic.h"
#include "ut_helpers.h"

extern BOOL g_bSystemInfoInitialized;
extern SYSTEM_INFO g_SystemInfo;

#define PXCH_INITHOOK_SYMBOL_NAME_X64 "InitHook"
#ifdef __CYGWIN__
#define PXCH_INITHOOK_SYMBOL_NAME_X86 "InitHook@4"
#else
#define PXCH_INITHOOK_SYMBOL_NAME_X86 "_InitHook@4"
#endif

PXCH_DLL_API DWORD __stdcall InitHook(PXCH_INJECT_REMOTE_DATA * pData);
PXCH_DLL_API DWORD __stdcall InitHookForMain(PROXYCHAINS_CONFIG * pConfig);
PXCH_DLL_API void UninitHook(void);

#define CreateProcessA_SIGN(inside_identifier) BOOL (WINAPI inside_identifier)(\
	LPCSTR lpApplicationName,\
	LPSTR lpCommandLine,\
	LPSECURITY_ATTRIBUTES lpProcessAttributes,\
	LPSECURITY_ATTRIBUTES lpThreadAttributes,\
	BOOL bInheritHandles,\
	DWORD dwCreationFlags,\
	LPVOID lpEnvironment,\
	LPCSTR lpCurrentDirectory,\
	LPSTARTUPINFOA lpStartupInfo,\
	LPPROCESS_INFORMATION lpProcessInformation)

#define CreateProcessW_SIGN(inside_identifier) BOOL (WINAPI inside_identifier)(\
	LPCWSTR lpApplicationName,\
	LPWSTR lpCommandLine,\
	LPSECURITY_ATTRIBUTES lpProcessAttributes,\
	LPSECURITY_ATTRIBUTES lpThreadAttributes,\
	BOOL bInheritHandles,\
	DWORD dwCreationFlags,\
	LPVOID lpEnvironment,\
	LPCWSTR lpCurrentDirectory,\
	LPSTARTUPINFOW lpStartupInfo,\
	LPPROCESS_INFORMATION lpProcessInformation)

#define CreateProcessAsUserW_SIGN(inside_identifier) BOOL (WINAPI inside_identifier)(\
	HANDLE hToken,\
	LPCWSTR lpApplicationName,\
	LPWSTR lpCommandLine,\
	LPSECURITY_ATTRIBUTES lpProcessAttributes,\
	LPSECURITY_ATTRIBUTES lpThreadAttributes,\
	BOOL bInheritHandles,\
	DWORD dwCreationFlags,\
	LPVOID lpEnvironment,\
	LPCWSTR lpCurrentDirectory,\
	LPSTARTUPINFOW lpStartupInfo,\
	LPPROCESS_INFORMATION lpProcessInformation)



#define Ws2_32_WSAStartup_SIGN(inside_identifier) int (__stdcall inside_identifier)(\
	PXCH_UINT16 wVersionRequested,\
	void* lpWSAData)

#define Ws2_32_WSAConnect_ARGLIST \
	PXCH_UINT_PTR s,\
	const void* name,\
	int namelen,\
	void* lpCallerData,\
	void* lpCalleeData,\
	void* lpSQOS,\
	void* lpGQOS

#define Ws2_32_WSAConnect_SIGN(inside_identifier) int (__stdcall inside_identifier)(Ws2_32_WSAConnect_ARGLIST)

#define Ws2_32_WSAConnect_SIGN_WITH_PTEMPDATA(inside_identifier) int (__stdcall inside_identifier)(void* pTempData, Ws2_32_WSAConnect_ARGLIST)



#define Ws2_32_connect_ARGLIST \
	/* SOCKET */PXCH_UINT_PTR s,\
	const /*struct sockaddr*/ void* name,\
	int namelen

#define Ws2_32_connect_SIGN(inside_identifier) int (__stdcall inside_identifier)(Ws2_32_connect_ARGLIST)

#define Ws2_32_connect_SIGN_WITH_PTEMPDATA(inside_identifier) int (__stdcall inside_identifier)(void* pTempData, Ws2_32_connect_ARGLIST)



#define Mswsock_ConnectEx_ARGLIST \
	/* SOCKET */PXCH_UINT_PTR s,\
	const void* name,\
	int namelen,\
	void* lpSendBuffer,\
	PXCH_UINT32 dwSendDataLength,\
	PXCH_UINT32* lpdwBytesSent,\
	void* lpOverlapped

#define Mswsock_ConnectEx_SIGN(inside_identifier) int (__stdcall inside_identifier)(Mswsock_ConnectEx_ARGLIST)

#define Mswsock_ConnectEx_SIGN_WITH_PTEMPDATA(inside_identifier) int (__stdcall inside_identifier)(void* pTempData, Mswsock_ConnectEx_ARGLIST)



#define Ws2_32_gethostbyname_SIGN(inside_identifier) void* /* struct hostent * */(__stdcall inside_identifier)(const char* name)



#define Ws2_32_gethostbyaddr_SIGN(inside_identifier) void* /* struct hostent* */(__stdcall inside_identifier)(\
	const char* addr,\
	int len,\
	int type)



#define Ws2_32_getaddrinfo_SIGN(inside_identifier) int (__stdcall inside_identifier)(const char* pNodeName, const char* pServiceName, const void* /* const ADDRINFOA* */ pHints, void* /* PADDRINFOA* */ ppResult)



#define Ws2_32_GetAddrInfoW_SIGN(inside_identifier) int (__stdcall inside_identifier)(\
	const wchar_t* pNodeName,\
	const wchar_t* pServiceName,\
	const void* /* const ADDRINFOW* */ pHints,\
	void* /* PADDRINFOW* */ ppResult)



#define Ws2_32_GetAddrInfoExA_SIGN(inside_identifier) int (__stdcall inside_identifier)(\
    const char* pName,\
    const char* pServiceName,\
    PXCH_UINT32 dwNameSpace,\
    void*/* LPGUID */ lpNspId,\
    const void* /* const ADDRINFOEXA * */ hints,\
    void*/* PADDRINFOEXA * */ ppResult,\
    void* /* struct timeval * */ timeout,\
    void* /* LPOVERLAPPED */ lpOverlapped,\
    void* /* LPLOOKUPSERVICE_COMPLETION_ROUTINE */ lpCompletionRoutine,\
	void* /* LPHANDLE */ lpHandle)



#define Ws2_32_GetAddrInfoExW_SIGN(inside_identifier) int (__stdcall inside_identifier)(\
    const wchar_t* pName,\
    const wchar_t* pServiceName,\
    PXCH_UINT32 dwNameSpace,\
    void*/* LPGUID */ lpNspId,\
    const void* /* const ADDRINFOEXW * */ hints,\
    void*/* PADDRINFOEXW * */ ppResult,\
    void* /* struct timeval * */ timeout,\
    void* /* LPOVERLAPPED */ lpOverlapped,\
    void* /* LPLOOKUPSERVICE_COMPLETION_ROUTINE */ lpCompletionRoutine,\
	void* /* LPHANDLE */ lpHandle)



#define Ws2_32_freeaddrinfo_SIGN(inside_identifier) void (__stdcall inside_identifier)(void* /* PADDRINFOA */ pAddrInfo)



#define Ws2_32_FreeAddrInfoW_SIGN(inside_identifier) void (__stdcall inside_identifier)(void* /* PADDRINFOW */ pAddrInfo)



#define Ws2_32_FreeAddrInfoExA__SIGN(inside_identifier) void (__stdcall inside_identifier)(void* /* PADDRINFOEXA */ pAddrInfoEx)



#define Ws2_32_FreeAddrInfoExW_SIGN(inside_identifier) void (__stdcall inside_identifier)(void* /* PADDRINFOEXW */ pAddrInfoEx)



#define Ws2_32_getnameinfo_SIGN(inside_identifier) int (__stdcall inside_identifier)(\
	const void* /* const SOCKADDR * */ pSockaddr,\
	int /* socklen_t */ SockaddrLength,\
	char* pNodeBuffer,\
	PXCH_UINT32 /* DWORD */ NodeBufferSize,\
	char* pServiceBuffer,\
	PXCH_UINT32 /* DWORD */ ServiceBufferSize, \
	int Flags)



#define Ws2_32_GetNameInfoW_SIGN(inside_identifier) int (__stdcall inside_identifier)(\
	const void* /* const SOCKADDR * */ pSockaddr,\
	int /* socklen_t */ SockaddrLength,\
	wchar_t* pNodeBuffer,\
	PXCH_UINT32 /* DWORD */ NodeBufferSize,\
	wchar_t* pServiceBuffer,\
	PXCH_UINT32 /* DWORD */ ServiceBufferSize, \
	int Flags)



extern FP_ORIGINAL_FUNC(CreateProcessA);
DECLARE_HOOK_FUNC(CreateProcessA);

extern FP_ORIGINAL_FUNC(CreateProcessW);
DECLARE_HOOK_FUNC(CreateProcessW);

extern FP_ORIGINAL_FUNC(CreateProcessAsUserW);
DECLARE_HOOK_FUNC(CreateProcessAsUserW);

extern FP_ORIGINAL_FUNC2(Ws2_32, WSAStartup);
DECLARE_HOOK_FUNC2(Ws2_32, WSAStartup);

extern FP_ORIGINAL_FUNC2(Mswsock, ConnectEx);
DECLARE_HOOK_FUNC2(Mswsock, ConnectEx);

extern FP_ORIGINAL_FUNC2(Ws2_32, connect);
DECLARE_HOOK_FUNC2(Ws2_32, connect);

extern FP_ORIGINAL_FUNC2(Ws2_32, WSAConnect);
DECLARE_HOOK_FUNC2(Ws2_32, WSAConnect);

extern FP_ORIGINAL_FUNC2(Ws2_32, gethostbyname);
DECLARE_HOOK_FUNC2(Ws2_32, gethostbyname);

extern FP_ORIGINAL_FUNC2(Ws2_32, gethostbyaddr);
DECLARE_HOOK_FUNC2(Ws2_32, gethostbyaddr);

extern FP_ORIGINAL_FUNC2(Ws2_32, getaddrinfo);
DECLARE_HOOK_FUNC2(Ws2_32, getaddrinfo);

extern FP_ORIGINAL_FUNC2(Ws2_32, GetAddrInfoW);
DECLARE_HOOK_FUNC2(Ws2_32, GetAddrInfoW);

extern FP_ORIGINAL_FUNC2(Ws2_32, GetAddrInfoExA);
DECLARE_HOOK_FUNC2(Ws2_32, GetAddrInfoExA);

extern FP_ORIGINAL_FUNC2(Ws2_32, GetAddrInfoExW);
DECLARE_HOOK_FUNC2(Ws2_32, GetAddrInfoExW);

extern FP_ORIGINAL_FUNC2(Ws2_32, freeaddrinfo);
DECLARE_HOOK_FUNC2(Ws2_32, freeaddrinfo);

extern FP_ORIGINAL_FUNC2(Ws2_32, FreeAddrInfoW);
DECLARE_HOOK_FUNC2(Ws2_32, FreeAddrInfoW);

extern FP_ORIGINAL_FUNC2(Ws2_32, FreeAddrInfoExA_);
DECLARE_HOOK_FUNC2(Ws2_32, FreeAddrInfoExA_);

extern FP_ORIGINAL_FUNC2(Ws2_32, FreeAddrInfoExW);
DECLARE_HOOK_FUNC2(Ws2_32, FreeAddrInfoExW);

extern FP_ORIGINAL_FUNC2(Ws2_32, getnameinfo);
DECLARE_HOOK_FUNC2(Ws2_32, getnameinfo);

extern FP_ORIGINAL_FUNC2(Ws2_32, GetNameInfoW);
DECLARE_HOOK_FUNC2(Ws2_32, GetNameInfoW);

// DECLARE_PROXY_FUNC2(Wsock32, connect);

PXCH_DLL_API int Ws2_32_DirectConnect(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen);
PXCH_DLL_API int Ws2_32_Socks5Connect(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen);
PXCH_DLL_API int Ws2_32_Socks5Handshake(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */);

extern UT_array* g_arrHeapAllocatedPointers;