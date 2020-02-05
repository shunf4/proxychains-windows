#pragma once

#include "includes_win32.h"
#include "defines_generic.h"

typedef HMODULE(WINAPI* FpGetModuleHandleW)(LPCWSTR);
typedef HMODULE(WINAPI* FpLoadLibraryW)(LPCWSTR);
typedef FARPROC(WINAPI* FpGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL (WINAPI* FpFreeLibrary)(HMODULE);
typedef DWORD(WINAPI* FpGetLastError)(VOID);
typedef VOID (WINAPI* FpOutputDebugStringA)(LPCSTR);


typedef struct _PXCH_INJECT_REMOTE_DATA {
	PXCH_UINT32 dwSize;
	PXCH_UINT32 dwEverExecuted;

	DWORD dwParentPid;
	DWORD dwDebugDepth;

	FpGetModuleHandleW fpGetModuleHandleW;
	FpLoadLibraryW fpLoadLibraryW;
	FpGetProcAddress fpGetProcAddress;
	FpFreeLibrary fpFreeLibrary;
	FpGetLastError fpGetLastError;
	FpOutputDebugStringA fpOutputDebugStringA;

	struct _PXCH_INJECT_REMOTE_DATA* pSavedRemoteData;
	PROXYCHAINS_CONFIG* pSavedPxchConfig;

	CHAR szInitFuncName[MAX_DLL_FUNC_NAME_BUFSIZE];
	CHAR szCIWCVarName[MAX_DLL_FUNC_NAME_BUFSIZE];

	char chDebugOutput[40];

	WCHAR szCygwin1ModuleName[MAX_DLL_FILE_NAME_BUFSIZE];
	WCHAR szHookDllModuleName[MAX_DLL_FILE_NAME_BUFSIZE];

	DWORD dwErrorCode;
	PROXYCHAINS_CONFIG pxchConfig;

} PXCH_INJECT_REMOTE_DATA;


extern PXCHDLL_API BOOL g_bCurrentlyInWinapiCall;
extern PXCHDLL_API DWORD g_dwCurrentProcessIdForVerify;
