#pragma once

#define WIN32_LEAN_AND_MEAN
#include <WinDef.h>
#include <tchar.h>

#ifdef PXCHDLL_EXPORTS
#define PXCHDLL_API __declspec(dllexport)
#else
#define PXCHDLL_API __declspec(dllimport)
#endif


#define MAX_DLL_PATH_BUFSIZE 1024
#define MAX_CONFIG_FILE_PATH_BUFSIZE 1024
#define MAX_DLL_FUNC_NAME_BUFSIZE 64
#define MAX_COMMAND_EXEC_PATH_BUFSIZE 512
#define MAX_COMMAND_LINE_BUFSIZE 65536

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

#define FP_ORIGINAL_FUNC(name) name##_SIGN(*fp##name) = name
#define DECLARE_PROXY_FUNC(name) PXCHDLL_API name##_SIGN(Proxy##name)
#define PROXY_FUNC(name) FP_ORIGINAL_FUNC(name); PXCHDLL_API name##_SIGN(Proxy##name)
#define CREATE_HOOK(name) do {MH_CreateHook((LPVOID)&name, (LPVOID)&Proxy##name, (LPVOID*)&fp##name);} while(0)


typedef struct _PROXYCHAINS_CONFIG {
	DWORD testNum;
	BOOL quiet;
	_TCHAR szConfigPath[MAX_CONFIG_FILE_PATH_BUFSIZE];
	_TCHAR szDllPath[MAX_DLL_PATH_BUFSIZE];
	_TCHAR szCommandLine[MAX_COMMAND_LINE_BUFSIZE];
} PROXYCHAINS_CONFIG;

#ifdef UNICODE
typedef HMODULE(WINAPI* FpGetModuleHandle)(LPCWSTR);
typedef HMODULE(WINAPI* FpLoadLibrary)(LPCWSTR);
typedef int (__CRTDECL* FpFtprintf)(FILE* const, wchar_t const* const, ...);
#else
typedef HMODULE(WINAPI* FpGetModuleHandle)(LPCSTR);
typedef HMODULE(WINAPI* FpLoadLibrary)(LPCSTR);
typedef int (__CRTDECL* FpFtprintf)(FILE* const, char const* const, ...);
#endif

typedef FARPROC(WINAPI* FpGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL (WINAPI* FpFreeLibrary)(HMODULE);
typedef DWORD (WINAPI* FpGetLastError)(VOID);

typedef struct _INJECT_REMOTE_DATA {
	UINT32 uStructSize;
	UINT32 uEverExecuted;

	FpGetModuleHandle fpGetModuleHandle;
	FpLoadLibrary fpLoadLibrary;
	FpGetProcAddress fpGetProcAddress;
	FpFreeLibrary fpFreeLibrary;
	FpGetLastError fpGetLastError;

	CHAR szInitFuncName[MAX_DLL_FUNC_NAME_BUFSIZE];

	DWORD dwErrorCode;
	PROXYCHAINS_CONFIG pxchConfig;
} INJECT_REMOTE_DATA;

static const _TCHAR szDllFileName[] = _T("proxychains_hook.dll");
extern PXCHDLL_API PROXYCHAINS_CONFIG* pPxchConfig;

DWORD WINAPI LoadHookDll(LPVOID* pArg);
void* LoadHookDll_End(void);
PXCHDLL_API DWORD __stdcall InitHook(INJECT_REMOTE_DATA* pData);
PXCHDLL_API DWORD __stdcall InitHookForMain(void);
PXCHDLL_API void UninitHook(void);
DECLARE_PROXY_FUNC(CreateProcessW);