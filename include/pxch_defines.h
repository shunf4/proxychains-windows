#pragma once

#ifndef __PXCH_DEFINES_H__
#define __PXCH_DEFINES_H__

#include "stdafx.h"
#include "dll.h"

// In characters -- start
#define MAX_DLL_PATH_BUFSIZE 512
#define MAX_CONFIG_FILE_PATH_BUFSIZE 512
#define MAX_DLL_FILE_NAME_BUFSIZE 64
#define MAX_DLL_FUNC_NAME_BUFSIZE 64
#define MAX_IPC_PIPE_NAME_BUFSIZE 128
#define MAX_COMMAND_EXEC_PATH_BUFSIZE 512
#define MAX_COMMAND_LINE_BUFSIZE 1024
#define MAX_REMOTE_LOG_BUFSIZE 256
#define MAX_HOSTNAME_BUFSIZE 256
// In characters -- end

typedef struct _PROXYCHAINS_CONFIG {
	DWORD testNum;
	DWORD dwMasterProcessId;
	BOOL bQuiet;
#ifdef __CYGWIN__
	pid_t pidCygwinSoleChildProc;
#endif
	WCHAR szIpcPipeName[MAX_IPC_PIPE_NAME_BUFSIZE];
	WCHAR szConfigPath[MAX_CONFIG_FILE_PATH_BUFSIZE];
	WCHAR szHookDllPath[MAX_DLL_PATH_BUFSIZE];
	WCHAR szMinHookDllPath[MAX_DLL_PATH_BUFSIZE];
	WCHAR szCommandLine[MAX_COMMAND_LINE_BUFSIZE];
} PROXYCHAINS_CONFIG;


typedef HMODULE(WINAPI* FpGetModuleHandleW)(LPCWSTR);
typedef HMODULE(WINAPI* FpLoadLibraryW)(LPCWSTR);
typedef FARPROC(WINAPI* FpGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL (WINAPI* FpFreeLibrary)(HMODULE);
typedef DWORD(WINAPI* FpGetLastError)(VOID);
typedef VOID (WINAPI* FpOutputDebugStringA)(LPCSTR);

typedef struct _INJECT_REMOTE_DATA {
	UINT32 uStructSize;
	UINT32 uEverExecuted;

	DWORD dwParentPid;
	DWORD dwDebugDepth;

	FpGetModuleHandleW fpGetModuleHandleW;
	FpLoadLibraryW fpLoadLibraryW;
	FpGetProcAddress fpGetProcAddress;
	FpFreeLibrary fpFreeLibrary;
	FpGetLastError fpGetLastError;
	FpOutputDebugStringA fpOutputDebugStringA;

	struct _INJECT_REMOTE_DATA* pSavedRemoteData;
	PROXYCHAINS_CONFIG* pSavedProxychainsConfig;

	CHAR szInitFuncName[MAX_DLL_FUNC_NAME_BUFSIZE];
	CHAR szCIWCVarName[MAX_DLL_FUNC_NAME_BUFSIZE];
	char chDebugOutput[40];
	WCHAR szCygwin1ModuleName[MAX_DLL_FILE_NAME_BUFSIZE];
	WCHAR szHookDllModuleName[MAX_DLL_FILE_NAME_BUFSIZE];

	DWORD dwErrorCode;
	PROXYCHAINS_CONFIG pxchConfig;

} INJECT_REMOTE_DATA;

#ifdef __CYGWIN__
static const WCHAR g_szHookDllFileName[] = L"cygproxychains_hook.dll";
#else
static const WCHAR g_szHookDllFileName[] = L"proxychains_hook.dll";
#endif
static const WCHAR g_szMinHookDllFileName[] = L"MinHook.x64.dll";
extern PXCHDLL_API PROXYCHAINS_CONFIG* g_pPxchConfig;

#ifdef __CYGWIN__
#define IF_CYGWIN_EXIT(code) do {exit(0);} while(0)
#define IF_WIN32_EXIT(code) do {} while(0)
#else
#define IF_CYGWIN_EXIT(code) do {} while(0)
#define IF_WIN32_EXIT(code) do {exit(0);} while(0)
#endif

#endif