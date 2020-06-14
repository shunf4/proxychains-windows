// SPDX-License-Identifier: GPL-2.0-or-later
/* defines_generic.h
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

#include "includes_generic.h"

#ifdef __CYGWIN__
#define _byteswap_uint64 __builtin_bswap64
typedef __UINT16_TYPE__ PXCH_UINT16;
typedef __INT32_TYPE__ PXCH_INT32;
typedef __UINT32_TYPE__ PXCH_UINT32;
typedef __UINT64_TYPE__ PXCH_UINT64;
#ifdef _WIN64
typedef __UINT64_TYPE__ PXCH_UINT_PTR;
#else
typedef unsigned int PXCH_UINT_PTR;
#endif
#else
typedef unsigned __int16 PXCH_UINT16;
typedef __int32 PXCH_INT32;
typedef unsigned __int32 PXCH_UINT32;
typedef unsigned __int64 PXCH_UINT64;
#ifdef _WIN64
typedef unsigned __int64 PXCH_UINT_PTR;
#else
typedef unsigned int PXCH_UINT_PTR;
#endif
#endif

#if defined(_M_X64) || defined(__x86_64__)
typedef PXCH_UINT64 PXCH_UINT_MACHINE;
#else
typedef PXCH_UINT32 PXCH_UINT_MACHINE;
#endif

#ifdef _DEBUG
#define IsDebug() (1)
#else
#define IsDebug() (0)
#endif

#if defined(_M_X64) || defined(__x86_64__)
#define IsX64() (1)
#else
#define IsX64() (0)
#endif

#if defined(_M_X64) || defined(__x86_64__)
#define PXCH_FUNCTION_SUFFIX_ARCH X64
#else
#define PXCH_FUNCTION_SUFFIX_ARCH X86
#endif

#define PXCH_WITH_SUFFIX_ARCH_XX(func, arch) func##arch
#define PXCH_WITH_SUFFIX_ARCH_X(func, arch) PXCH_WITH_SUFFIX_ARCH_XX(func, arch)
#define PXCH_WITH_SUFFIX_ARCH(func) PXCH_WITH_SUFFIX_ARCH_X(func, PXCH_FUNCTION_SUFFIX_ARCH)

// printf narrow string specifier
// Only used in non-ipc log. When using ipc log, use "%ls" for wide string, and "%S" for narrow string
#ifdef __CYGWIN__
#define WPRS L"%s"
#else
#define WPRS L"%S"
#endif

#ifdef _LP64
#define PRIdword  "u"
#define PRIudword "u"
#else
#define PRIdword  "lu"
#define PRIudword "lu"
#endif

#define _PREFIX_L(s) L ## s
#define PREFIX_L(s) _PREFIX_L(s)

#define WPRDW L"%" PREFIX_L(PRIdword)

#ifndef _countof
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

// In characters -- start
#define PXCH_MAX_DLL_PATH_BUFSIZE 512
#define PXCH_MAX_CONFIG_FILE_PATH_BUFSIZE 512
#define PXCH_MAX_BIN_FILE_PATH_BUFSIZE 512
#define PXCH_MAX_HELPER_PATH_BUFSIZE 512
#define PXCH_MAX_HOSTS_FILE_PATH_BUFSIZE 512
#define PXCH_MAX_DLL_FILE_NAME_BUFSIZE 64
#define PXCH_MAX_DLL_FUNC_NAME_BUFSIZE 64
#define PXCH_MAX_IPC_PIPE_NAME_BUFSIZE 128
#define PXCH_MAX_COMMAND_EXEC_PATH_BUFSIZE 512
#define PXCH_MAX_COMMAND_LINE_BUFSIZE 1024
#define PXCH_MAX_HOSTNAME_BUFSIZE 256
#define PXCH_MAX_USERNAME_BUFSIZE 256
#define PXCH_MAX_PASSWORD_BUFSIZE 256
#define PXCH_MAX_PROXY_NUM 5
#define PXCH_MAX_FILEMAPPING_BUFSIZE 256
#define PXCH_MAX_CONFIGURATION_LINE_BUFSIZE 512
#define PXCH_MAX_HOSTS_LINE_BUFSIZE 512
#define PXCH_MAX_ERROR_MESSAGE_BUFSIZE 256
#define PXCH_MAX_DUMP_MEMORY_BUFSIZE 1024
#define PXCH_MAX_FORMAT_HOST_PORT_BUFSIZE 512
#define PXCH_MAX_ARRAY_IP_NUM_PER_FAMILY 5
#define PXCH_MAX_ARRAY_IP_NUM (PXCH_MAX_ARRAY_IP_NUM_PER_FAMILY * 2)
#define PXCH_MAX_PATHEXT_BUFSIZE 256

#define PXCH_LOG_IPC_BUFSIZE 1024
#define PXCH_LOG_ODS_BUFSIZE 256

#define PXCH_MAX_FWPRINTF_BUFSIZE 1024	// Also as log bufsize
// In characters -- end

#ifdef __CYGWIN__
#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif
#endif

#define PXCH_PROXY_TYPE_MASK    0x000000FF
#define PXCH_PROXY_TYPE_INVALID 0x00000000
#define PXCH_PROXY_TYPE_SOCKS5  0x00000001
#define PXCH_PROXY_TYPE_DIRECT  0x000000FF

#define PXCH_PROXY_STATE_MASK      0x0000FF00
#define PXCH_PROXY_STATE_INVALID   0x00000000
#define PXCH_PROXY_STATE_UNUSABLE  0x0000F000
#define PXCH_PROXY_STATE_BLOCK     0x0000F100
#define PXCH_PROXY_STATE_IDLE      0x00000100

#define ProxyInit(x) *((PXCH_UINT32*)(&x)) = 0

#define ProxyIsType(type, x) (((x).dwTag & PXCH_PROXY_TYPE_MASK) == PXCH_PROXY_TYPE_##type)
#define ProxyIsState(type, x) (((x).dwTag & PXCH_PROXY_STATE_MASK) == PXCH_PROXY_STATE_##type)
#define ProxyIsInvalid(x) ((((x).dwTag & PXCH_PROXY_TYPE_MASK) == PXCH_PROXY_TYPE_INVALID) || (((x).dwTag & PXCH_PROXY_STATE_MASK) == PXCH_PROXY_STATE_INVALID))

#define SetProxyType(type, x) (x).dwTag = ((x).dwTag & ~PXCH_PROXY_TYPE_MASK) | PXCH_PROXY_TYPE_##type
#define SetProxyState(type, x) (x).dwTag = ((x).dwTag & ~PXCH_PROXY_STATE_MASK) | PXCH_PROXY_STATE_##type


#define PXCH_RULE_TYPE_DOMAIN_KEYWORD   0x00000001
#define PXCH_RULE_TYPE_DOMAIN_SUFFIX    0x00000002
#define PXCH_RULE_TYPE_DOMAIN_FULL      0x00000003
#define PXCH_RULE_TYPE_DOMAIN           0x00000003
#define PXCH_RULE_TYPE_IP_CIDR          0x00000004
#define PXCH_RULE_TYPE_PORT             0x00000005
#define PXCH_RULE_TYPE_FINAL            0x00000006
#define PXCH_RULE_TYPE_INVALID          0x00000000

#define PXCH_RULE_TARGET_PROXY          0x00000001
#define PXCH_RULE_TARGET_DIRECT         0x00000000
#define PXCH_RULE_TARGET_BLOCK          0x00000002

#define RuleInit(x) (x).dwTag = PXCH_RULE_TYPE_INVALID

#define RuleIsType(type, x) ((x).dwTag == PXCH_RULE_TYPE_##type)
#define RuleIsInvalid(x) RuleIsType(INVALID, x)

#define SetRuleType(type, x) (x).dwTag = PXCH_RULE_TYPE_##type


#define PXCH_HOST_TYPE_INVALID   USHRT_MAX
#define PXCH_HOST_TYPE_HOSTNAME  (USHRT_MAX - 1)
#define PXCH_HOST_TYPE_IPV4      2		// AF_INET
#define PXCH_HOST_TYPE_IPV6      23     // AF_INET6

#define HostInit(x) *((PXCH_UINT16*)(&x)) = 0

#define HostIsType(type, x) (((const PXCH_HOST*)&(x))->wTag == PXCH_HOST_TYPE_##type)
#define HostIsIp(x) (((const PXCH_HOST*)&(x))->wTag == PXCH_HOST_TYPE_IPV4 || ((const PXCH_HOST*)&(x))->wTag == PXCH_HOST_TYPE_IPV6)
#define HostIsInvalid(x) HostIsType(INVALID, x)

#define SetHostType(type, x) ((PXCH_HOST*)&(x))->wTag = PXCH_HOST_TYPE_##type


#ifdef PXCH_DLL_EXPORTS
#define PXCH_DLL_API __declspec(dllexport)	// Cygwin gcc also recognizes this
#else
#define PXCH_DLL_API __declspec(dllimport)
#endif


#ifdef __CYGWIN__
#define IF_CYGWIN_EXIT(code) do { LOGI(L"Master exiting"); exit(code); } while(0)
#define IF_WIN32_EXIT(code) do {} while(0)
#else
#define IF_CYGWIN_EXIT(code) do {} while(0)
#define IF_WIN32_EXIT(code) do { LOGI(L"Master exiting"); exit(code); } while(0)
#endif

#if !defined(__CYGWIN__) || defined(PXCH_MSYS_USE_WIN32_STYLE)
#define IF_WIN32_STYLE_EXIT(code) do { LOGI(L"Master exiting"); exit(code); } while(0)
#else
#define IF_WIN32_STYLE_EXIT(code) do {} while(0)
#endif

// Consistent with sockaddr
#pragma pack(push, 1)
typedef struct _PXCH_SOCKADDR {
	PXCH_UINT16 wTag;
	char Data[128 - 2];
} PXCH_SOCKADDR;
#pragma pack(pop)

typedef union {
	PXCH_SOCKADDR Sockaddr;
	struct {
		PXCH_UINT16 wTag;
		PXCH_UINT16 wPort;	// Network order
	} CommonHeader;
} PXCH_IP_PORT;
typedef PXCH_IP_PORT PXCH_IP_ADDRESS;   // port must be zero

typedef wchar_t PXCH_HOSTNAME_VALUE[PXCH_MAX_HOSTNAME_BUFSIZE];
typedef char PXCH_USERNAME[PXCH_MAX_USERNAME_BUFSIZE];
typedef char PXCH_PASSWORD[PXCH_MAX_USERNAME_BUFSIZE];


typedef struct _PXCH_HOSTNAME {
	PXCH_UINT16 wTag;
	PXCH_UINT16 wPort;	// Network order
	PXCH_HOSTNAME_VALUE szValue;
} PXCH_HOSTNAME_PORT;

typedef PXCH_HOSTNAME_PORT PXCH_HOSTNAME;  // port must be zero

typedef union _PXCH_HOST {
	PXCH_UINT16 wTag;

	struct {
		PXCH_UINT16 wTag;
		PXCH_UINT16 wPort;	// Network order
	} CommonHeader;

	PXCH_HOSTNAME_PORT HostnamePort;
	PXCH_IP_PORT IpPort;
} PXCH_HOST_PORT;

typedef PXCH_HOST_PORT PXCH_HOST;  // port must be zero

union _PXCH_PROXY_DATA;

// Now that myself (*pProxy) is already connected, do handshake in ways of myself (*pProxy)
typedef int(*PXCH_WS2_32_FPHANDSHAKE)(void* pTempData, PXCH_UINT_PTR s, const union _PXCH_PROXY_DATA* pProxy /* Mostly myself */);

// Now that myself (*pProxy) is already connected, and handshake is already done, connect to *pHostPort through myself (*pProxy)
typedef int(*PXCH_WS2_32_FPCONNECT)(void* pTempData, PXCH_UINT_PTR s, const union _PXCH_PROXY_DATA* pProxy /* Mostly myself */, const PXCH_HOST_PORT* pHostPort, int iAddrLen);

typedef struct _PXCH_PROXY_DIRECT_DATA {
	PXCH_UINT32 dwTag;
	// PXCH_WS2_32_FPCONNECT Ws2_32_FpConnect;
	// PXCH_WS2_32_FPHANDSHAKE Ws2_32_FpHandshake;
	char Ws2_32_ConnectFunctionName[PXCH_MAX_DLL_FUNC_NAME_BUFSIZE];
	char Ws2_32_HandshakeFunctionName[PXCH_MAX_DLL_FUNC_NAME_BUFSIZE];
	PXCH_HOST_PORT HostPort;
	int iAddrLen;
} PXCH_PROXY_DIRECT_DATA;

typedef struct _PXCH_PROXY_SOCKS5_DATA {
	PXCH_UINT32 dwTag;
	// PXCH_WS2_32_FPCONNECT Ws2_32_FpConnect;
	// PXCH_WS2_32_FPHANDSHAKE Ws2_32_FpHandshake;
	char Ws2_32_ConnectFunctionName[PXCH_MAX_DLL_FUNC_NAME_BUFSIZE];
	char Ws2_32_HandshakeFunctionName[PXCH_MAX_DLL_FUNC_NAME_BUFSIZE];
	PXCH_HOST_PORT HostPort;
	int iAddrLen;

	PXCH_USERNAME szUsername;
	PXCH_PASSWORD szPassword;
} PXCH_PROXY_SOCKS5_DATA;


typedef union _PXCH_PROXY_DATA {
	PXCH_UINT32 dwTag;

	struct {
		PXCH_UINT32 dwTag;
		// PXCH_WS2_32_FPCONNECT Ws2_32_FpConnect;
		// PXCH_WS2_32_FPHANDSHAKE Ws2_32_FpHandshake;
		char Ws2_32_ConnectFunctionName[PXCH_MAX_DLL_FUNC_NAME_BUFSIZE];
		char Ws2_32_HandshakeFunctionName[PXCH_MAX_DLL_FUNC_NAME_BUFSIZE];
		PXCH_HOST_PORT HostPort;
		int iAddrLen;
	} CommonHeader;

	PXCH_PROXY_SOCKS5_DATA Socks5;
	PXCH_PROXY_DIRECT_DATA Direct;
} PXCH_PROXY_DATA;


typedef struct _PXCH_RULE {
	PXCH_UINT32 dwTag;

	PXCH_HOST_PORT HostPort;
	PXCH_UINT32 dwCidrPrefixLength;
	
	PXCH_UINT32 dwTarget;
} PXCH_RULE;


typedef struct _PXCH_HOSTS_ENTRY {
	PXCH_HOSTNAME Hostname;
	PXCH_IP_ADDRESS Ip;
} PXCH_HOSTS_ENTRY;


#define PXCH_CONFIG_EXTRA_SIZE_G PXCH_CONFIG_EXTRA_SIZE(g_pPxchConfig)
#define PXCH_CONFIG_EXTRA_SIZE_BY_N(proxyNum, ruleNum, hostsEntryNum, remoteFuncX64SizeInBytes, remoteFuncX86SizeInBytes) ((sizeof(PXCH_PROXY_DATA) * proxyNum) + (sizeof(PXCH_RULE) * ruleNum) + (sizeof(PXCH_HOSTS_ENTRY) * hostsEntryNum) + remoteFuncX64SizeInBytes + remoteFuncX86SizeInBytes)
#define PXCH_CONFIG_EXTRA_SIZE(pPxchConfig) PXCH_CONFIG_EXTRA_SIZE_BY_N((pPxchConfig)->dwProxyNum, (pPxchConfig)->dwRuleNum, (pPxchConfig)->dwHostsEntryNum, (pPxchConfig)->cbRemoteFuncX64Size, (pPxchConfig)->cbRemoteFuncX86Size)

#define PXCH_CONFIG_PROXY_ARR(pPxchConfig) ((PXCH_PROXY_DATA*)((char*)(pPxchConfig) + pPxchConfig->cbProxyListOffset))
#define PXCH_CONFIG_RULE_ARR(pPxchConfig) ((PXCH_RULE*)((char*)(pPxchConfig) + pPxchConfig->cbRuleListOffset))
#define PXCH_CONFIG_HOSTS_ENTRY_ARR(pPxchConfig) ((PXCH_HOSTS_ENTRY*)((char*)(pPxchConfig) + pPxchConfig->cbHostsEntryListOffset))
#define PXCH_CONFIG_REMOTE_FUNC_X64(pPxchConfig) ((char*)((char*)(pPxchConfig) + pPxchConfig->cbRemoteFuncX64Offset))
#define PXCH_CONFIG_REMOTE_FUNC_X86(pPxchConfig) ((char*)((char*)(pPxchConfig) + pPxchConfig->cbRemoteFuncX86Offset))

#define PXCH_CONFIG_PROXY_ARR_G PXCH_CONFIG_PROXY_ARR(g_pPxchConfig)
#define PXCH_CONFIG_RULE_ARR_G PXCH_CONFIG_RULE_ARR(g_pPxchConfig)
#define PXCH_CONFIG_HOSTS_ENTRY_ARR_G PXCH_CONFIG_HOSTS_ENTRY_ARR(g_pPxchConfig)

#pragma pack(push, 1)
typedef struct _PROXYCHAINS_CONFIG {
	PXCH_UINT32 dwMasterProcessId;
	PXCH_INT32 dwLogLevel;
	PXCH_INT32 dwLogLevelSetByArg;
	wchar_t szIpcPipeName[PXCH_MAX_IPC_PIPE_NAME_BUFSIZE];
	wchar_t szConfigPath[PXCH_MAX_CONFIG_FILE_PATH_BUFSIZE];
	wchar_t szHookDllPathX86[PXCH_MAX_DLL_PATH_BUFSIZE];
	wchar_t szHookDllPathX64[PXCH_MAX_DLL_PATH_BUFSIZE];
	wchar_t szMinHookDllPathX86[PXCH_MAX_DLL_PATH_BUFSIZE];
	wchar_t szMinHookDllPathX64[PXCH_MAX_DLL_PATH_BUFSIZE];
	wchar_t szHostsFilePath[PXCH_MAX_HOSTS_FILE_PATH_BUFSIZE];
	wchar_t szCommandLine[PXCH_MAX_COMMAND_LINE_BUFSIZE];

	struct {
		PXCH_UINT64 fpGetModuleHandleWX64;
		PXCH_UINT64 fpLoadLibraryWX64;
		PXCH_UINT64 fpGetProcAddressX64;
		PXCH_UINT64 fpFreeLibraryX64;
		PXCH_UINT64 fpGetLastErrorX64;
		PXCH_UINT64 fpOutputDebugStringAX64;
		PXCH_UINT64 fpGetCurrentProcessIdX64;
		PXCH_UINT64 fpwsprintfAX64;
		PXCH_UINT64 fpSleepX64;
		PXCH_UINT64 fpExitThreadX64;
		PXCH_UINT64 fpReleaseSemaphoreX64;
		PXCH_UINT64 fpCloseHandleX64;
		PXCH_UINT64 fpWaitForSingleObjectX64;

		PXCH_UINT64 fpGetModuleHandleWX86;
		PXCH_UINT64 fpLoadLibraryWX86;
		PXCH_UINT64 fpGetProcAddressX86;
		PXCH_UINT64 fpFreeLibraryX86;
		PXCH_UINT64 fpGetLastErrorX86;
		PXCH_UINT64 fpOutputDebugStringAX86;
		PXCH_UINT64 fpGetCurrentProcessIdX86;
		PXCH_UINT64 fpwsprintfAX86;
		PXCH_UINT64 fpSleepX86;
		PXCH_UINT64 fpExitThreadX86;
		PXCH_UINT64 fpReleaseSemaphoreX86;
		PXCH_UINT64 fpCloseHandleX86;
		PXCH_UINT64 fpWaitForSingleObjectX86;
	} FunctionPointers;
	
	PXCH_UINT32 cbProxyListOffset;
	PXCH_UINT32 dwProxyNum;

	PXCH_UINT32 cbRuleListOffset;
	PXCH_UINT32 dwRuleNum;

	PXCH_UINT32 cbHostsEntryListOffset;
	PXCH_UINT32 dwHostsEntryNum;

	PXCH_UINT32 cbRemoteFuncX64Offset;
	PXCH_UINT32 cbRemoteFuncX64Size;

	PXCH_UINT32 cbRemoteFuncX86Offset;
	PXCH_UINT32 cbRemoteFuncX86Size;

	PXCH_IP_ADDRESS FakeIpv4Range;
	PXCH_UINT32 dwFakeIpv4PrefixLength;

	PXCH_IP_ADDRESS FakeIpv6Range;
	PXCH_UINT32 dwFakeIpv6PrefixLength;

	PXCH_UINT32 dwDefaultTarget;

	PXCH_UINT32 dwProxyConnectionTimeoutMillisecond;	// Only take effect in non-blocking sockets (We simply use connect() to do connect)
	PXCH_UINT32 dwProxyHandshakeTimeoutMillisecond;	// Only take effect in non-blocking sockets (We simply use send() and recv())

	PXCH_UINT32 dwWillUseUdpAssociateAsRemoteDns;
	PXCH_UINT32 dwWillUseFakeIpAsRemoteDns;
	PXCH_UINT32 dwWillDeleteFakeIpAfterChildProcessExits;
	PXCH_UINT32 dwWillUseFakeIpWhenHostnameNotMatched;	// usually exclusive with dwWillMapResolvedIpToHost
	PXCH_UINT32 dwWillMapResolvedIpToHost;
	PXCH_UINT32 dwWillLookupForHostByResolvedIp;
	PXCH_UINT32 dwWillResolveLocallyIfMatchHosts;
	PXCH_UINT32 dwWillGenFakeIpUsingHashedHostname;

	PXCH_UINT32 dwWillFirstTunnelUseIpv4;
	PXCH_UINT32 dwWillFirstTunnelUseIpv6;
} PROXYCHAINS_CONFIG;
#pragma pack(pop)

static const wchar_t g_szChildDataSavingFileMappingPrefix[] = L"Local\\proxychains_child_data_";

#ifdef _DEBUG
#define PXCH_HOOKDLL_DEBUG_SUFFIX L"d"
#define PXCH_HOOKDLL_DEBUG_SUFFIX_NARROW "d"
#else
#define PXCH_HOOKDLL_DEBUG_SUFFIX L""
#define PXCH_HOOKDLL_DEBUG_SUFFIX_NARROW ""
#endif

// Deprecated
#define PXCH_DUMP_REMOTE_FUNCTION_X64_PATH "proxychains_remote_function_x64" PXCH_HOOKDLL_DEBUG_SUFFIX_NARROW ".bin"
#define PXCH_DUMP_REMOTE_FUNCTION_X86_PATH "proxychains_remote_function_x86" PXCH_HOOKDLL_DEBUG_SUFFIX_NARROW ".bin"

#if __CYGWIN__
#define PXCH_REDIRECT_NULL_FILE "/dev/null"
#else
#define PXCH_REDIRECT_NULL_FILE "nul"
#endif

#ifdef __CYGWIN__
#ifdef PXCH_IS_MSYS
#define PXCH_HOOKDLL_CYGWIN_PREFIX L"msys-"
#else
#define PXCH_HOOKDLL_CYGWIN_PREFIX L"cyg"
#endif
#else
#define PXCH_HOOKDLL_CYGWIN_PREFIX L""
#endif

#ifdef __CYGWIN__
#ifdef PXCH_IS_MSYS
#define PXCH_HELPER_OS_DESC "msys"
#else
#define PXCH_HELPER_OS_DESC "cygwin"
#endif
#else
#define PXCH_HELPER_OS_DESC "win32"
#endif

#define PXCH_HELPER_X64_COMMANDLINE_SUFFIX "proxychains_helper_" PXCH_HELPER_OS_DESC "_x64" PXCH_HOOKDLL_DEBUG_SUFFIX_NARROW ".exe --get-winapi-func-addr 2> " PXCH_REDIRECT_NULL_FILE
#define PXCH_HELPER_X86_COMMANDLINE_SUFFIX "proxychains_helper_" PXCH_HELPER_OS_DESC "_x86" PXCH_HOOKDLL_DEBUG_SUFFIX_NARROW ".exe --get-winapi-func-addr 2> " PXCH_REDIRECT_NULL_FILE


#if defined(_M_X64) || defined(__x86_64__)
#define PXCH_HOOKDLL_ARCHITECT_SUFFIX L"_x64"
#define szMinHookDllPath szMinHookDllPathX64
#define szHookDllPath szHookDllPathX64
#define PXCH_DUMP_REMOTE_FUNCTION_PATH PXCH_DUMP_REMOTE_FUNCTION_X64_PATH
#else
#define PXCH_HOOKDLL_ARCHITECT_SUFFIX L"_x86"
#define szMinHookDllPath szMinHookDllPathX86
#define szHookDllPath szHookDllPathX86
#define PXCH_DUMP_REMOTE_FUNCTION_PATH PXCH_DUMP_REMOTE_FUNCTION_X86_PATH
#endif

static const wchar_t g_szHookDllFileName[] = PXCH_HOOKDLL_CYGWIN_PREFIX L"proxychains_hook" PXCH_HOOKDLL_ARCHITECT_SUFFIX PXCH_HOOKDLL_DEBUG_SUFFIX L".dll";
static const wchar_t g_szHookDllFileNameX64[] = PXCH_HOOKDLL_CYGWIN_PREFIX L"proxychains_hook_x64" PXCH_HOOKDLL_DEBUG_SUFFIX L".dll";
static const wchar_t g_szHookDllFileNameX86[] = PXCH_HOOKDLL_CYGWIN_PREFIX L"proxychains_hook_x86" PXCH_HOOKDLL_DEBUG_SUFFIX L".dll";

static const wchar_t g_szMinHookDllFileNameX64[] = L"MinHook.x64.dll";
static const wchar_t g_szMinHookDllFileNameX86[] = L"MinHook.x86.dll";

#if defined(_M_X64) || defined(__x86_64__)
static const wchar_t g_szMinHookDllFileName[] = L"MinHook.x64.dll";
#else
static const wchar_t g_szMinHookDllFileName[] = L"MinHook.x86.dll";
#endif

PXCH_DLL_API  extern PROXYCHAINS_CONFIG* g_pPxchConfig;
