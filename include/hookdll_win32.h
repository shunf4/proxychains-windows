#pragma once

#include "defines_win32.h"
#include "hookdll_generic.h"

PXCHDLL_API DWORD __stdcall InitHook(PXCH_INJECT_REMOTE_DATA * pData);
PXCHDLL_API DWORD __stdcall InitHookForMain(PROXYCHAINS_CONFIG * pConfig);
PXCHDLL_API void UninitHook(void);
PXCHDLL_API HANDLE g_hIpcServerSemaphore;


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

#define Ws2_32_connect_SIGN(inside_identifier) int (__stdcall inside_identifier)(\
	/* SOCKET */PXCH_UINT_PTR s,\
	const /*struct sockaddr*/ void* name,\
	int namelen)

//DECLARE_PROXY_FUNC(CreateProcessA);
extern FP_ORIGINAL_FUNC(CreateProcessW);
DECLARE_HOOK_FUNC(CreateProcessW);

extern FP_ORIGINAL_FUNC(CreateProcessAsUserW);
DECLARE_HOOK_FUNC(CreateProcessAsUserW);

extern FP_ORIGINAL_FUNC2(Ws2_32, connect);
DECLARE_HOOK_FUNC2(Ws2_32, connect);

// DECLARE_PROXY_FUNC2(Wsock32, connect);

PXCHDLL_API int Ws2_32DirectConnect(PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen);
PXCHDLL_API int Ws2_32Socks5Connect(PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen);
PXCHDLL_API int Ws2_32Socks5Handshake(PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */);
