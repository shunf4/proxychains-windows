#pragma once

#ifndef __PXCH_HOOK_H__
#define __PXCH_HOOK_H__

#include "stdafx.h"
#include "dll.h"
#include "pxch_defines.h"

#ifdef __CYGWIN__
#define PXCHDLL_NOT_SUPPORTING_CYGWIN FALSE
#else
#define PXCHDLL_NOT_SUPPORTING_CYGWIN TRUE
#endif

#define CreateProcessA_SIGN(name) BOOL (WINAPI name)(\
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

#define CreateProcessW_SIGN(name) BOOL (WINAPI name)(\
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

#define CreateProcessAsUserW_SIGN(name) BOOL (WINAPI name)(\
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

#define FP_ORIGINAL_FUNC(name) name##_SIGN(*fp##name) = name
#define DECLARE_PROXY_FUNC(name) PXCHDLL_API name##_SIGN(Proxy##name)
#define PROXY_FUNC(name) FP_ORIGINAL_FUNC(name); PXCHDLL_API name##_SIGN(Proxy##name)
#define CREATE_HOOK(name) do {MH_CreateHook((LPVOID)&name, (LPVOID)&Proxy##name, (LPVOID*)&fp##name);} while(0)
#define CREATE_HOOK_ALT(prefix, name) do {MH_CreateHook((LPVOID)&name, (LPVOID)&prefix##Proxy##name, (LPVOID*)&fp##name);} while(0)

// MSVC arranges these functions in alphabetical order
DWORD __stdcall LoadHookDll(LPVOID* pArg);
void* LoadHookDll_End(void);

PXCHDLL_API DWORD __stdcall InitHook(INJECT_REMOTE_DATA* pData);
PXCHDLL_API DWORD __stdcall InitHookForMain(PROXYCHAINS_CONFIG *pConfig);
PXCHDLL_API BOOL g_bCurrentlyInWinapiCall;
PXCHDLL_API void UninitHook(void);

PXCHDLL_API HANDLE g_hIpcServerSemaphore;

//DECLARE_PROXY_FUNC(CreateProcessA);
DECLARE_PROXY_FUNC(CreateProcessW);
DECLARE_PROXY_FUNC(CreateProcessAsUserW);

#endif