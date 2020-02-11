#pragma once

#include "include_generic.h"

#ifdef __CYGWIN__
#define _byteswap_uint64 _bswap64
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
#define MAX_DLL_PATH_BUFSIZE 512
#define MAX_CONFIG_FILE_PATH_BUFSIZE 512
#define MAX_DLL_FILE_NAME_BUFSIZE 64
#define MAX_DLL_FUNC_NAME_BUFSIZE 64
#define MAX_IPC_PIPE_NAME_BUFSIZE 128
#define MAX_COMMAND_EXEC_PATH_BUFSIZE 512
#define MAX_COMMAND_LINE_BUFSIZE 1024
#define MAX_HOSTNAME_BUFSIZE 256
#define MAX_USERNAME_BUFSIZE 256
#define MAX_PASSWORD_BUFSIZE 256
#define MAX_PROXY_NUM 5
#define MAX_FILEMAPPING_BUFSIZE 256
#define MAX_ARRAY_IP_NUM 10

#define PXCH_LOG_IPC_BUFSIZE 1024
#define PXCH_LOG_ODS_BUFSIZE 256

#define MAX_FWPRINTF_BUFSIZE 1024	// Also as log bufsize
// In characters -- end

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

typedef wchar_t PXCH_HOSTNAME_VALUE[MAX_HOSTNAME_BUFSIZE];
typedef char PXCH_USERNAME[MAX_USERNAME_BUFSIZE];
typedef char PXCH_PASSWORD[MAX_USERNAME_BUFSIZE];


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
	char Ws2_32_ConnectFunctionName[MAX_DLL_FUNC_NAME_BUFSIZE];
	char Ws2_32_HandshakeFunctionName[MAX_DLL_FUNC_NAME_BUFSIZE];
	PXCH_HOST_PORT HostPort;
	int iAddrLen;
} PXCH_PROXY_DIRECT_DATA;

typedef struct _PXCH_PROXY_SOCKS5_DATA {
	PXCH_UINT32 dwTag;
	// PXCH_WS2_32_FPCONNECT Ws2_32_FpConnect;
	// PXCH_WS2_32_FPHANDSHAKE Ws2_32_FpHandshake;
	char Ws2_32_ConnectFunctionName[MAX_DLL_FUNC_NAME_BUFSIZE];
	char Ws2_32_HandshakeFunctionName[MAX_DLL_FUNC_NAME_BUFSIZE];
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
		char Ws2_32_ConnectFunctionName[MAX_DLL_FUNC_NAME_BUFSIZE];
		char Ws2_32_HandshakeFunctionName[MAX_DLL_FUNC_NAME_BUFSIZE];
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
	
	PXCH_UINT32 iWillProxy;
} PXCH_RULE;


typedef struct _PXCH_HOSTS_ENTRY {
	PXCH_HOSTNAME Hostname;
	PXCH_IP_ADDRESS Ip;
} PXCH_HOSTS_ENTRY;


#define PXCHCONFIG_EXTRA_SIZE(pPxchConfig) ((sizeof(PXCH_RULE) * (pPxchConfig)->dwRuleNum) + (sizeof(PXCH_PROXY_DATA) * (pPxchConfig)->dwProxyNum))
#define PXCHCONFIG_EXTRA_SIZE_G PXCHCONFIG_EXTRA_SIZE(g_pPxchConfig)
#define PXCHCONFIG_EXTRA_SIZE_BY_N(proxyNum, ruleNum, hostsEntryNum) ((sizeof(PXCH_RULE) * ruleNum) + (sizeof(PXCH_PROXY_DATA) * proxyNum) + (sizeof(PXCH_HOSTS_ENTRY) * hostsEntryNum))

#define PXCHCONFIG_PROXY_ARR(pPxchConfig) ((PXCH_PROXY_DATA*)((char*)(pPxchConfig) + pPxchConfig->cbProxyListOffset))
#define PXCHCONFIG_RULE_ARR(pPxchConfig) ((PXCH_RULE*)((char*)(pPxchConfig) + pPxchConfig->cbRuleListOffset))
#define PXCHCONFIG_HOSTS_ENTRY_ARR(pPxchConfig) ((PXCH_HOSTS_ENTRY*)((char*)(pPxchConfig) + pPxchConfig->cbHostsEntryListOffset))

#define PXCHCONFIG_PROXY_ARR_G PXCHCONFIG_PROXY_ARR(g_pPxchConfig)
#define PXCHCONFIG_RULE_ARR_G PXCHCONFIG_RULE_ARR(g_pPxchConfig)
#define PXCHCONFIG_HOSTS_ENTRY_ARR_G PXCHCONFIG_HOSTS_ENTRY_ARR(g_pPxchConfig)


typedef struct _PROXYCHAINS_CONFIG {
	PXCH_UINT32 dwMasterProcessId;
	PXCH_INT32 dwIsQuiet;
	PXCH_INT32 dwIsQuietAlreadySet;
	wchar_t szIpcPipeName[MAX_IPC_PIPE_NAME_BUFSIZE];
	wchar_t szConfigPath[MAX_CONFIG_FILE_PATH_BUFSIZE];
	wchar_t szHookDllPath[MAX_DLL_PATH_BUFSIZE];
	wchar_t szMinHookDllPath[MAX_DLL_PATH_BUFSIZE];
	wchar_t szCommandLine[MAX_COMMAND_LINE_BUFSIZE];
	
	PXCH_UINT32 cbProxyListOffset;
	PXCH_UINT32 dwProxyNum;

	PXCH_UINT32 cbRuleListOffset;
	PXCH_UINT32 dwRuleNum;

	PXCH_UINT32 cbHostsEntryListOffset;
	PXCH_UINT32 dwHostsEntryNum;

	PXCH_IP_ADDRESS FakeIpv4Range;
	PXCH_UINT32 dwFakeIpv4PrefixLength;

	PXCH_IP_ADDRESS FakeIpv6Range;
	PXCH_UINT32 dwFakeIpv6PrefixLength;

	PXCH_UINT32 dwProxyConnectionTimeoutMillisecond;	// Only take effect in non-blocking sockets (We simply use connect() to do connect)
	PXCH_UINT32 dwProxyHandshakeTimeoutMillisecond;	// Only take effect in non-blocking sockets (We simply use send() and recv())

	PXCH_UINT32 dwWillUseUdpAssociateAsRemoteDns;
	PXCH_UINT32 dwWillUseFakeIpAsRemoteDns;
	PXCH_UINT32 dwWillDeleteFakeIpAfterChildProcessExits;
	PXCH_UINT32 dwWillUseFakeIpWhenHostnameNotMatched;	// usually exclusive with dwWillMapResolvedIpToHost
	PXCH_UINT32 dwWillMapResolvedIpToHost;
	PXCH_UINT32 dwWillSearchForHostByResolvedIp;
	PXCH_UINT32 dwWillForceResolveByHostsFile;

	PXCH_UINT32 dwWillFirstTunnelUseIpv4;
	PXCH_UINT32 dwWillFirstTunnelUseIpv6;
} PROXYCHAINS_CONFIG;

static const wchar_t g_szChildDataSavingFileMappingPrefix[] = L"Local\\proxychains_child_data_";

#ifdef __CYGWIN__
static const wchar_t g_szHookDllFileName[] = L"cygproxychains_hook.dll";
#else
static const wchar_t g_szHookDllFileName[] = L"proxychains_hook.dll";
#endif

#if defined(_M_X64) || defined(__x86_64__)
static const wchar_t g_szMinHookDllFileName[] = L"MinHook.x64.dll";
#else
static const wchar_t g_szMinHookDllFileName[] = L"MinHook.x86.dll";
#endif

extern PXCH_DLL_API PROXYCHAINS_CONFIG* g_pPxchConfig;
