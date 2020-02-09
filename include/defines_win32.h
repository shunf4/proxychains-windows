#pragma once

#include "includes_win32.h"
#include "defines_generic.h"

#define PXCH_DO_IN_CRITICAL_SECTION_RETURN_DWORD \
	DWORD dwReturn = 0; \
	int iLock; \
	HeapLock(GetProcessHeap()); \
	goto lock_critical_section_start; \
lock_after_critical_section: \
	HeapUnlock(GetProcessHeap()); \
	return dwReturn; \
 \
lock_critical_section_start: \
for (iLock = 0; ; iLock++) \
if (iLock > 0) goto lock_after_critical_section; \
else


#define PXCH_DO_IN_CRITICAL_SECTION_RETURN_VOID \
	int iLock; \
	HeapLock(GetProcessHeap()); \
	goto lock_critical_section_start; \
lock_after_critical_section: \
	HeapUnlock(GetProcessHeap()); \
	return; \
 \
lock_critical_section_start: \
for (iLock = 0; ; iLock++) \
if (iLock > 0) goto lock_after_critical_section; \
else


#define PXCH_TLS_PTR_W32HOSTENT_BY_BASE(base) ((struct hostent*)((char*)base + PXCH_TLS_OFFSET_W32HOSTENT))
#define PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_BY_BASE(base) ((PXCH_UINT32**)((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_IP_PTR_LIST))
#define PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_AS_PPCHAR_BY_BASE(base) ((char**)((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_IP_PTR_LIST))
#define PXCH_TLS_PTR_W32HOSTENT_IP_BUF_BY_BASE(base) ((PXCH_UINT32*)((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_IP_BUF))
#define PXCH_TLS_PTR_W32HOSTENT_ALIAS_PTR_LIST_BY_BASE(base) ((char(**)[PXCH_TLS_W32HOSTENT_ALIAS_BUFSIZE])((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_ALIAS_PTR_LIST))
#define PXCH_TLS_PTR_W32HOSTENT_ALIAS_BUF_BY_BASE(base) ((char(*)[PXCH_TLS_W32HOSTENT_ALIAS_BUFSIZE])((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_ALIAS_BUF))
#define PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF_BY_BASE(base) ((char(*)[MAX_HOSTNAME_BUFSIZE])((char*)base + PXCH_TLS_OFFSET_W32HOSTENT_HOSTNAME_BUF))

#define PXCH_TLS_PTR_W32HOSTENT(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_AS_PPCHAR(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_IP_PTR_LIST_AS_PPCHAR_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_IP_BUF(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_IP_BUF_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_ALIAS_PTR_LIST(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_ALIAS_PTR_LIST_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_ALIAS_BUF(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_ALIAS_BUF_BY_BASE(TlsGetValue(dwTlsIndex))
#define PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF(dwTlsIndex) PXCH_TLS_PTR_W32HOSTENT_HOSTNAME_BUF_BY_BASE(TlsGetValue(dwTlsIndex))


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
