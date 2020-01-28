#pragma once

#ifndef __PXCH_DEFINES_H__
#define __PXCH_DEFINES_H__

#include "stdafx.h"
#include "dll.h"

#define MAX_DLL_PATH_BUFSIZE 1024
#define MAX_CONFIG_FILE_PATH_BUFSIZE 1024
#define MAX_DLL_FUNC_NAME_BUFSIZE 64
#define MAX_COMMAND_EXEC_PATH_BUFSIZE 512
#define MAX_COMMAND_LINE_BUFSIZE 65536

typedef struct _PROXYCHAINS_CONFIG {
	DWORD testNum;
	BOOL quiet;
	WCHAR szConfigPath[MAX_CONFIG_FILE_PATH_BUFSIZE];
	WCHAR szDllPath[MAX_DLL_PATH_BUFSIZE];
	WCHAR szCommandLine[MAX_COMMAND_LINE_BUFSIZE];
} PROXYCHAINS_CONFIG;


typedef HMODULE(WINAPI* FpGetModuleHandleW)(LPCWSTR);
typedef HMODULE(WINAPI* FpLoadLibraryW)(LPCWSTR);
typedef FARPROC(WINAPI* FpGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL (WINAPI* FpFreeLibrary)(HMODULE);
typedef DWORD (WINAPI* FpGetLastError)(VOID);

typedef struct _INJECT_REMOTE_DATA {
	UINT32 uStructSize;
	UINT32 uEverExecuted;

	FpGetModuleHandleW fpGetModuleHandleW;
	FpLoadLibraryW fpLoadLibraryW;
	FpGetProcAddress fpGetProcAddress;
	FpFreeLibrary fpFreeLibrary;
	FpGetLastError fpGetLastError;

	CHAR szInitFuncName[MAX_DLL_FUNC_NAME_BUFSIZE];

	DWORD dwErrorCode;
	PROXYCHAINS_CONFIG pxchConfig;
} INJECT_REMOTE_DATA;

#ifdef __CYGWIN__
static const WCHAR szDllFileName[] = L"cygproxychains_hook.dll";
#else
static const WCHAR szDllFileName[] = L"proxychains_hook.dll";
#endif
extern PXCHDLL_API PROXYCHAINS_CONFIG* pPxchConfig;

#endif