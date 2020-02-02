#pragma once

#include "includes_win32.h"
#include "defines_generic.h"

typedef struct _PROXYCHAINS_CONFIG {
	DWORD testNum;
	DWORD dwMasterProcessId;
	BOOL bQuiet;
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
	PXCH_UINT32 uStructSize;
	PXCH_UINT32 uEverExecuted;

	DWORD dwParentPid;
	DWORD dwDebugDepth;

	FpGetModuleHandleW fpGetModuleHandleW;
	FpLoadLibraryW fpLoadLibraryW;
	FpGetProcAddress fpGetProcAddress;
	FpFreeLibrary fpFreeLibrary;
	FpGetLastError fpGetLastError;
	FpOutputDebugStringA fpOutputDebugStringA;

	struct _INJECT_REMOTE_DATA* pSavedRemoteData;
	PROXYCHAINS_CONFIG* pSavedPxchConfig;

	CHAR szInitFuncName[MAX_DLL_FUNC_NAME_BUFSIZE];
	CHAR szCIWCVarName[MAX_DLL_FUNC_NAME_BUFSIZE];

	char chDebugOutput[40];

	WCHAR szCygwin1ModuleName[MAX_DLL_FILE_NAME_BUFSIZE];
	WCHAR szHookDllModuleName[MAX_DLL_FILE_NAME_BUFSIZE];

	DWORD dwErrorCode;
	PROXYCHAINS_CONFIG pxchConfig;

} INJECT_REMOTE_DATA;


extern PXCHDLL_API PROXYCHAINS_CONFIG* g_pPxchConfig;
extern PXCHDLL_API BOOL g_bCurrentlyInWinapiCall;

