#pragma once

#include "defines_win32.h"
#include "hookdll_generic.h"

PXCHDLL_API DWORD __stdcall InitHook(PXCH_INJECT_REMOTE_DATA * pData);
PXCHDLL_API DWORD __stdcall InitHookForMain(PROXYCHAINS_CONFIG * pConfig);
PXCHDLL_API void UninitHook(void);

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



//DECLARE_PROXY_FUNC(CreateProcessA);
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

// DECLARE_PROXY_FUNC2(Wsock32, connect);

PXCHDLL_API int Ws2_32_DirectConnect(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen);
PXCHDLL_API int Ws2_32_Socks5Connect(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen);
PXCHDLL_API int Ws2_32_Socks5Handshake(void* pTempData, PXCH_UINT_PTR s, const PXCH_PROXY_DATA* pProxy /* Mostly myself */);
