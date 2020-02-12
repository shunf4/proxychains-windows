#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#define PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#include "includes_win32.h"
#include <Shlwapi.h>
#include <Winsock2.h>
#include <wchar.h>
#include <inttypes.h>
#include <strsafe.h>

#include "defines_win32.h"
#include "log_win32.h"
#include "hookdll_win32.h"

#ifndef __CYGWIN__
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#endif

#define PXCH_CONFIG_PARSE_WHITE L" \n\t\r\v"
#define PXCH_CONFIG_PARSE_DIGIT L"0123456789"
#define WSTR_EQUAL(str, after_validate, literal) ((wcsncmp(str, literal, _countof(literal) - 1) == 0) ? (after_validate == str + _countof(literal) - 1) : FALSE)

static const WCHAR* pszParseErrorMessage;

static inline size_t SizeMin(size_t a, size_t b)
{
	return a > b ? b : a;
}

static inline BOOL ArgHasSpecialChar(WCHAR* sz)
{
	WCHAR* p = sz;
	while (*p) {
		if (*p == L' ') return TRUE;
		if (*p == L'\t') return TRUE;
		if (*p == L'\n') return TRUE;
		if (*p == L'\v') return TRUE;
		if (*p == L'\"') return TRUE;
		p++;
	}
	return FALSE;
}

static inline BOOL CharInSet(WCHAR* pStart, const WCHAR* pCharset)
{
	const WCHAR* pSet;
	for (pSet = pCharset; *pSet; pSet++) {
		if (*pStart == *pSet) return TRUE;
	}
    return FALSE;
}

static inline WCHAR* ConsumeStringUntilSet(WCHAR* pStart, const WCHAR* pCharset)
{
    WCHAR* p;
    const WCHAR* pSet;
    for (p = pStart; *p; p++) {
        for (pSet = pCharset; *pSet; pSet++) {
            if (*p == *pSet) return p;
        }
    }
    return p;
}

static inline WCHAR* ConsumeStringInSet(WCHAR* pStart, const WCHAR* pCharset)
{
    WCHAR* p;
    const WCHAR* pSet;
    BOOL bContain;

    for (p = pStart; *p; p++) {
        bContain = FALSE;
        for (pSet = pCharset; *pSet; pSet++) {
            if (*p == *pSet) {
                bContain = TRUE;
                break;
            }
        }
        if (bContain) continue;
        return p;
    }
    return p;
}

static int OptionGetNumberValue(long* plNum, const WCHAR* pStart, long lRangeMin, long lRangeMax)
{
	const WCHAR* pAfterWhite;
	const WCHAR* pAfterNumber;
	const WCHAR* pAfterWhite2;
	long lResult;
	
	pAfterWhite = ConsumeStringInSet(pStart, PXCH_CONFIG_PARSE_WHITE L"=");
	if (pAfterWhite == pStart) {
		pszParseErrorMessage = L"No white space or = before value";
		return -1;
	}

	pAfterNumber = ConsumeStringInSet(pAfterWhite, PXCH_CONFIG_PARSE_DIGIT);
	if (pAfterNumber == pAfterWhite) {
		pszParseErrorMessage = L"No number value";
		return -1;
	}

	pAfterWhite2 = ConsumeStringInSet(pAfterNumber, PXCH_CONFIG_PARSE_WHITE);
	if (!CharInSet(pAfterWhite2, L"#\n") || *pAfterWhite2 == L'\0') {
		pszParseErrorMessage = L"Extra character after number value";
		return -1;
	}

	lResult = atoi(pAfterWhite);
	if (lResult < lRangeMin || lResult > lRangeMax) {
		pszParseErrorMessage = L"Number out of range";
		return -1;
	}

	*plNum = lResult;
	return 0;
}


DWORD LoadConfiguration(PROXYCHAINS_CONFIG** ppPxchConfig, PROXYCHAINS_CONFIG* pTempPxchConfig)
{
	DWORD dwLastError;
	WSADATA wsaData;
	DWORD dwRet;
	FILETIME ft;
	ULARGE_INTEGER uli;
	PROXYCHAINS_CONFIG* pPxchConfig;
	int iRuleNum;
	int iProxyNum;
	int iHostsEntryNum;
	int iDummy;
	WCHAR szConfigurationLine[MAX_CONFIGURATION_LINE_BUFSIZE];
	unsigned long long ullLineNum;
	BOOL bIntoProxyList;
	DWORD dwRuleNum = 0;
	long lRuleFirstLineOffset = -1;
	DWORD dwProxyNum = 0;
	long lProxyFirstLineOffset = -1;
	long lLastOffset;

	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// Default

	pPxchConfig = pTempPxchConfig;
	pPxchConfig->dwMasterProcessId = GetCurrentProcessId();

	GetSystemTimeAsFileTime(&ft);
	uli.HighPart = ft.dwHighDateTime;
	uli.LowPart = ft.dwLowDateTime;
	StringCchPrintfW(pPxchConfig->szIpcPipeName, _countof(pPxchConfig->szIpcPipeName), L"\\\\.\\pipe\\proxychains_" WPRDW L"_%" PREFIX_L(PRIu64) L"", GetCurrentProcessId(), uli.QuadPart);

	dwRet = GetModuleFileNameW(NULL, pPxchConfig->szHookDllPath, MAX_DLL_PATH_BUFSIZE);
	if (dwRet == 0) goto err_insuf_buf;
	if (dwRet == MAX_DLL_PATH_BUFSIZE) goto err_insuf_buf;

	if (!PathRemoveFileSpecW(pPxchConfig->szHookDllPath)) goto err_insuf_buf;

	if (FAILED(StringCchCatW(pPxchConfig->szHookDllPath, MAX_DLL_PATH_BUFSIZE, L"\\"))) goto err_insuf_buf;
	if (FAILED(StringCchCopyW(pPxchConfig->szMinHookDllPath, MAX_DLL_PATH_BUFSIZE, pPxchConfig->szHookDllPath))) goto err_insuf_buf;
	if (FAILED(StringCchCatW(pPxchConfig->szHookDllPath, MAX_DLL_PATH_BUFSIZE, g_szHookDllFileName))) goto err_insuf_buf;
	if (FAILED(StringCchCatW(pPxchConfig->szMinHookDllPath, MAX_DLL_PATH_BUFSIZE, g_szMinHookDllFileName))) goto err_insuf_buf;

	if (!PathFileExistsW(pPxchConfig->szHookDllPath)) goto err_dll_not_exist;
	if (!PathFileExistsW(pPxchConfig->szMinHookDllPath)) StringCchCopyW(pPxchConfig->szMinHookDllPath, MAX_DLL_PATH_BUFSIZE, g_szMinHookDllFileName);

	pPxchConfig->dwProxyConnectionTimeoutMillisecond = 3000;
	pPxchConfig->dwProxyHandshakeTimeoutMillisecond = 5000;

	pPxchConfig->dwWillFirstTunnelUseIpv4 = TRUE;
	pPxchConfig->dwWillFirstTunnelUseIpv6 = FALSE;

	iDummy = sizeof(PXCH_IP_ADDRESS);
	pPxchConfig->dwFakeIpv4PrefixLength = 8;
	WSAStringToAddressW(L"224.0.0.0", AF_INET, NULL, (LPSOCKADDR)&pPxchConfig->FakeIpv4Range, &iDummy);

	iDummy = sizeof(PXCH_IP_ADDRESS);
	pPxchConfig->dwFakeIpv6PrefixLength = 16;
	WSAStringToAddressW(L"250d::", AF_INET6, NULL, (LPSOCKADDR)&pPxchConfig->FakeIpv6Range, &iDummy);

	pPxchConfig->dwWillDeleteFakeIpAfterChildProcessExits = TRUE;
	pPxchConfig->dwWillUseFakeIpWhenHostnameNotMatched = TRUE;
	pPxchConfig->dwWillMapResolvedIpToHost = FALSE;
	pPxchConfig->dwWillSearchForHostByResolvedIp = FALSE;
	pPxchConfig->dwWillForceResolveByHostsFile = TRUE;
	pPxchConfig->dwWillUseUdpAssociateAsRemoteDns = FALSE;
	pPxchConfig->dwWillUseFakeIpAsRemoteDns = TRUE;

	// Parse configuration file

	if ((dwLastError = OpenConfigurationFile(pTempPxchConfig)) != NO_ERROR) goto err_general;
	if ((lLastOffset = ftell(GetConfigurationFile())) == -1) goto err_read_config2;

	while ((dwLastError = ConfigurationFileReadLine(&ullLineNum, szConfigurationLine, _countof(szConfigurationLine))) == NO_ERROR) {
		// wprintf(L"%ls Line %llu: %ls", pTempPxchConfig->szConfigPath, ullLineNum, szConfigurationLine);
		WCHAR* sOption;
		WCHAR* sOptionNameEnd;
		BOOL bHasValueSeparatedByWhite = FALSE;
		BOOL bHasValueSeparatedByComma = FALSE;
		long lValue;

		if (ullLineNum >= (1 << 31)) goto err_config_too_large;

		sOption = ConsumeStringInSet(szConfigurationLine, PXCH_CONFIG_PARSE_WHITE);
		if (*sOption == L'#' || *sOption == L'\0') continue;
		sOptionNameEnd = ConsumeStringUntilSet(sOption, PXCH_CONFIG_PARSE_WHITE L",#");

		// wprintf(L"Line %llu: %d, %.*ls\n", ullLineNum, (int)(sOptionNameEnd - sOption), sOptionNameEnd - sOption, sOption);

		if (WSTR_EQUAL(sOption, sOptionNameEnd, L"strict_chain")) {
			LOGD(L"Use strict chain");
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"random_chain")) {
			pszParseErrorMessage = L"random_chain is not supported!";
			goto err_invalid_config_with_msg;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"chain_len")) {
			pszParseErrorMessage = L"chain_len is not supported!";
			goto err_invalid_config_with_msg;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"quiet_mode")) {
			if (!pTempPxchConfig->dwLogLevelAlreadySet) {
				LOGD(L"Queit mode enabled in configuration file");
				pTempPxchConfig->dwLogLevel = PXCH_LOG_LEVEL_ERROR;
			}
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"proxy_dns")) {
			LOGD(L"Proxy dns using fake IP");
			pTempPxchConfig->dwWillUseFakeIpAsRemoteDns = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"proxy_dns_udp_associate")) {
			pszParseErrorMessage = L"proxy_dns_udp_associate is not supported!";
			goto err_invalid_config_with_msg;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"remote_dns_subnet")) {
			if (OptionGetNumberValue(&lValue, sOptionNameEnd, 0, 255) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwFakeIpv4PrefixLength = 8;
			ZeroMemory(&pPxchConfig->FakeIpv4Range, sizeof(pPxchConfig->FakeIpv4Range));
			((unsigned char*)&((struct sockaddr_in*)&pPxchConfig->FakeIpv4Range)->sin_addr)[0] = (unsigned char)lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"remote_dns_subnet_cidr_v4")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"remote_dns_subnet_cidr_v6")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"tcp_read_time_out")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"tcp_connect_time_out")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"localnet")) {
			if (lRuleFirstLineOffset < 0) lRuleFirstLineOffset = lLastOffset;
			dwRuleNum++;
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN-KEYWORD")) {
			if (lRuleFirstLineOffset < 0) lRuleFirstLineOffset = lLastOffset;
			dwRuleNum++;
			bHasValueSeparatedByComma = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN-SUFFIX")) {
			if (lRuleFirstLineOffset < 0) lRuleFirstLineOffset = lLastOffset;
			dwRuleNum++;
			bHasValueSeparatedByComma = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN-FULL") || WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN")) {
			if (lRuleFirstLineOffset < 0) lRuleFirstLineOffset = lLastOffset;
			dwRuleNum++;
			bHasValueSeparatedByComma = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"IP-CIDR")) {
			if (lRuleFirstLineOffset < 0) lRuleFirstLineOffset = lLastOffset;
			dwRuleNum++;
			bHasValueSeparatedByComma = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"PORT")) {
			if (lRuleFirstLineOffset < 0) lRuleFirstLineOffset = lLastOffset;
			dwRuleNum++;
			bHasValueSeparatedByComma = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"FINAL")) {
			if (lRuleFirstLineOffset < 0) lRuleFirstLineOffset = lLastOffset;
			dwRuleNum++;
			bHasValueSeparatedByComma = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"delete_fake_ip_after_child_exits")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"use_fake_ip_when_hostname_not_matched")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"map_resolved_ip_to_host")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"search_for_host_by_resolved_ip")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"force_resolve_by_hosts_file")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"first_tunnel_uses_ipv4")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"first_tunnel_uses_ipv6")) {
			bHasValueSeparatedByWhite = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"[ProxyList]")) {
			bIntoProxyList = TRUE;
			lProxyFirstLineOffset = lLastOffset;
		} else {
			LOGE(L"Line %llu: Unknown option: %.*ls", ullLineNum, sOptionNameEnd - sOption, sOption);
			goto err_invalid_config;
		}
	}

	if (dwLastError != ERROR_END_OF_MEDIA) goto err_read_config;

	iRuleNum = 5;
	iProxyNum = 1;
	iHostsEntryNum = 1;
	pPxchConfig = *ppPxchConfig = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PROXYCHAINS_CONFIG) + PXCHCONFIG_EXTRA_SIZE_BY_N(iProxyNum, iRuleNum, iHostsEntryNum));

	CopyMemory(pPxchConfig, pTempPxchConfig, sizeof(PROXYCHAINS_CONFIG));


	pPxchConfig->dwProxyNum = iProxyNum;
	pPxchConfig->cbProxyListOffset = sizeof(PROXYCHAINS_CONFIG);
	pPxchConfig->dwRuleNum = iRuleNum;
	pPxchConfig->cbRuleListOffset = sizeof(PROXYCHAINS_CONFIG) + (sizeof(PXCH_PROXY_DATA) * pPxchConfig->dwProxyNum);
	pPxchConfig->dwHostsEntryNum = iHostsEntryNum;
	pPxchConfig->cbHostsEntryListOffset = sizeof(PROXYCHAINS_CONFIG) + (sizeof(PXCH_PROXY_DATA) * pPxchConfig->dwProxyNum) + (sizeof(PXCH_RULE) * pPxchConfig->dwRuleNum);
	

	{
		PXCH_PROXY_DATA* proxy = &PXCHCONFIG_PROXY_ARR(pPxchConfig)[0];
		ProxyInit(*proxy);
		SetProxyType(SOCKS5, *proxy);
		SetHostType(IPV4, proxy->Socks5.HostPort);
		proxy->Socks5.iAddrLen = sizeof(proxy->Socks5.HostPort);
		// WSAStringToAddressW(L"127.0.0.1:1079", AF_INET, NULL, (LPSOCKADDR)&proxy->Socks5.HostPort, &proxy->Socks5.iAddrLen);
		proxy->Socks5.HostPort.wTag = PXCH_HOST_TYPE_HOSTNAME;
		proxy->Socks5.HostPort.CommonHeader.wPort = ntohs(1079);
		StringCchCopyW(proxy->Socks5.HostPort.HostnamePort.szValue, _countof(proxy->Socks5.HostPort.HostnamePort.szValue), L"localhost");

		proxy->Socks5.szUsername[0] = '\0';
		proxy->Socks5.szPassword[0] = '\0';
		StringCchCopyA(proxy->Socks5.Ws2_32_ConnectFunctionName, _countof(proxy->Socks5.Ws2_32_ConnectFunctionName), "Ws2_32_Socks5Connect");
		StringCchCopyA(proxy->Socks5.Ws2_32_HandshakeFunctionName, _countof(proxy->Socks5.Ws2_32_HandshakeFunctionName), "Ws2_32_Socks5Handshake");
	}

	{
		PXCH_RULE* rule = &PXCHCONFIG_RULE_ARR(pPxchConfig)[0];
		int iAddrLen = sizeof(PXCH_IP_ADDRESS);
		RuleInit(*rule);
		SetRuleType(IP_CIDR, *rule);

		ZeroMemory(&rule->HostPort, sizeof(rule->HostPort));
		SetHostType(IPV4, rule->HostPort);
		WSAStringToAddressW(L"127.0.0.1", AF_INET, NULL, (LPSOCKADDR)&rule->HostPort.IpPort, &iAddrLen);
		rule->dwCidrPrefixLength = 32;
		rule->dwTarget = PXCH_RULE_TARGET_DIRECT;
	}

	{
		PXCH_RULE* rule = &PXCHCONFIG_RULE_ARR(pPxchConfig)[1];
		int iAddrLen = sizeof(PXCH_IP_ADDRESS);
		RuleInit(*rule);
		SetRuleType(IP_CIDR, *rule);

		ZeroMemory(&rule->HostPort, sizeof(rule->HostPort));
		SetHostType(IPV4, rule->HostPort);
		WSAStringToAddressW(L"10.0.0.0", AF_INET, NULL, (LPSOCKADDR)&rule->HostPort.IpPort, &iAddrLen);
		rule->dwCidrPrefixLength = 8;
		rule->dwTarget = PXCH_RULE_TARGET_DIRECT;
	}

	{
		PXCH_RULE* rule = &PXCHCONFIG_RULE_ARR(pPxchConfig)[iRuleNum - 3];
		RuleInit(*rule);
		SetRuleType(DOMAIN_KEYWORD, *rule);

		ZeroMemory(&rule->HostPort, sizeof(rule->HostPort));
		SetHostType(HOSTNAME, rule->HostPort);
		StringCchCopyW(rule->HostPort.HostnamePort.szValue, _countof(rule->HostPort.HostnamePort.szValue), L"");
		rule->dwTarget = PXCH_RULE_TARGET_PROXY;
	}

	{
		PXCH_RULE* rule = &PXCHCONFIG_RULE_ARR(pPxchConfig)[iRuleNum - 2];
		int iAddrLen = sizeof(PXCH_IP_ADDRESS);
		RuleInit(*rule);
		SetRuleType(IP_CIDR, *rule);

		ZeroMemory(&rule->HostPort, sizeof(rule->HostPort));
		SetHostType(IPV6, rule->HostPort);
		WSAStringToAddressW(L"::", AF_INET6, NULL, (LPSOCKADDR)&rule->HostPort.IpPort, &iAddrLen);
		rule->dwCidrPrefixLength = 0;
		rule->dwTarget = PXCH_RULE_TARGET_PROXY;
	}

	{
		PXCH_RULE* rule = &PXCHCONFIG_RULE_ARR(pPxchConfig)[iRuleNum - 1];
		int iAddrLen = sizeof(PXCH_IP_ADDRESS);
		RuleInit(*rule);
		SetRuleType(IP_CIDR, *rule);

		ZeroMemory(&rule->HostPort, sizeof(rule->HostPort));
		SetHostType(IPV4, rule->HostPort);
		WSAStringToAddressW(L"0.0.0.0", AF_INET, NULL, (LPSOCKADDR)&rule->HostPort.IpPort, &iAddrLen);
		rule->dwCidrPrefixLength = 0;
		rule->dwTarget = PXCH_RULE_TARGET_PROXY;
	}

	{
		PXCH_HOSTS_ENTRY* pHostsEntry = &PXCHCONFIG_HOSTS_ENTRY_ARR(pPxchConfig)[0];
		int iAddrLen = sizeof(PXCH_IP_ADDRESS);
		WSAStringToAddressW(L"127.0.0.1", AF_INET, NULL, (LPSOCKADDR)&pHostsEntry->Ip, &iAddrLen);
		SetHostType(HOSTNAME, pHostsEntry->Hostname);
		StringCchCopyW(pHostsEntry->Hostname.szValue, sizeof(pHostsEntry->Hostname.szValue), L"myself.reserved");
	}

	return 0;

err_general:
	return dwLastError;
err_insuf_buf:
	return ERROR_INSUFFICIENT_BUFFER;
err_dll_not_exist:
	return ERROR_FILE_NOT_FOUND;
err_read_config:
	LOGE(L"Error reading configuration: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;
err_read_config2:
	LOGE(L"Error reading configuration.");
	return ERROR_READ_FAULT;
err_invalid_config_with_msg:
	LOGE(L"Line %llu: %ls", ullLineNum, pszParseErrorMessage);
err_invalid_config:
	return ERROR_BAD_CONFIGURATION;
err_config_too_large:
	return ERROR_FILE_TOO_LARGE;
}


DWORD ParseArgs(PROXYCHAINS_CONFIG* pConfig, int argc, WCHAR* argv[], int* piCommandStart)
{
	int i;
	int iCountCommands = 0;
	BOOL bOptionFile = FALSE;
	unsigned int iOptionPrefixLen;
	BOOL bOptionHasValue;
	BOOL bOptionsEnd = FALSE;
	BOOL bForceQuote = FALSE;
	DWORD dwErrorCode;
	WCHAR* pWchar;
	WCHAR* pCommandLine;

	pConfig->szConfigPath[0] = L'\0';
	pConfig->szCommandLine[0] = L'\0';
	pCommandLine = pConfig->szCommandLine;
	pConfig->dwLogLevel = PXCH_LOG_LEVEL_DEBUG;
	pConfig->dwLogLevelAlreadySet = FALSE;

	for (i = 1; i < argc; i++) {
		pWchar = argv[i];
		if (!bOptionsEnd) {

		option_value_following:
			if (bOptionFile) {
				if (FAILED(StringCchCopyW(pConfig->szConfigPath, _countof(pConfig->szConfigPath), pWchar))) goto err_insuf_buf;
				bOptionFile = FALSE;
				continue;
			}

			bOptionHasValue = FALSE;

			if (wcsncmp(pWchar, L"-f", 2) == 0) {
				bOptionFile = TRUE;
				iOptionPrefixLen = 2;
				bOptionHasValue = TRUE;
			}
			else if (wcsncmp(pWchar, L"-q", 2) == 0) {
				LOGD(L"Queit mode enabled in arguments");
				pConfig->dwLogLevel = PXCH_LOG_LEVEL_ERROR;
				pConfig->dwLogLevelAlreadySet = TRUE;
				continue;
			}
			else if (wcsncmp(pWchar, L"-Q", 2) == 0) {
				LOGD(L"Queit mode disabled in arguments");
				pConfig->dwLogLevel = PXCH_LOG_LEVEL_ERROR;
				pConfig->dwLogLevelAlreadySet = TRUE;
				continue;
			}
			else {
				bOptionsEnd = TRUE;
				i--;
				continue;
			}

			if (bOptionHasValue) {
				if (wcslen(pWchar) > iOptionPrefixLen) {
					pWchar += 2;
					goto option_value_following;
				}
				else continue;
			}
		}
		// else
		// Option Ends, Command starts
#ifdef __CYGWIN__
		* piCommandStart = i;
		return 0;
#endif
		LOGD(L"Argv[%d] = %ls", i, pWchar);
		iCountCommands++;
		if (iCountCommands > 1) {
			if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
				goto err_insuf_buf;
			}
			*(pCommandLine++) = L' ';
		}
		else {
			WCHAR szExecPath[MAX_COMMAND_EXEC_PATH_BUFSIZE];
			LPWSTR lpDummyFilePart;
			if (SearchPathW(NULL, pWchar, L"", _countof(szExecPath), szExecPath, &lpDummyFilePart) == 0) {
				if (SearchPathW(NULL, pWchar, L".exe", _countof(szExecPath), szExecPath, &lpDummyFilePart) == 0) {
					goto err_get_exec_path;
				}
			}
			pWchar = szExecPath;
		}

		if (!bForceQuote && *pWchar != L'\0' && !ArgHasSpecialChar(pWchar)) {
			if (FAILED(StringCchCopyEx(pCommandLine, _countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine), pWchar, &pCommandLine, NULL, 0))) goto err_insuf_buf;
		}
		else {
			if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
				goto err_insuf_buf;
			}
			*(pCommandLine++) = L'"';

			while (*pWchar) {
				UINT32 uCountBackslashes = 0;
				while (*pWchar && *pWchar == L'\\') {
					pWchar++;
					uCountBackslashes++;
				}
				if (*pWchar == L'\0') {
					UINT32 u;
					uCountBackslashes *= 2;
					for (u = 0; u < uCountBackslashes; u++) {
						if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
							goto err_insuf_buf;
						}
						*(pCommandLine++) = L'\\';
					}
				}
				else if (*pWchar == L'"') {
					UINT32 u;
					uCountBackslashes *= 2;
					uCountBackslashes += 1;
					for (u = 0; u < uCountBackslashes + 1; u++) {
						if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
							goto err_insuf_buf;
						}
						if (u != uCountBackslashes) {
							*(pCommandLine++) = L'\\';
						}
						else {
							*(pCommandLine++) = L'"';
						}
					}
				}
				else {
					UINT32 u;
					for (u = 0; u < uCountBackslashes + 1; u++) {
						if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
							goto err_insuf_buf;
						}
						if (u != uCountBackslashes) {
							*(pCommandLine++) = L'\\';
						}
						else {
							*(pCommandLine++) = *pWchar;
						}
					}
				}

				if (*pWchar == L'\0') {
					break;
				}
				pWchar++;
			}
			if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
				goto err_insuf_buf;
			}
			*(pCommandLine++) = L'"';
		}
	}
	*pCommandLine = L'\0';

	if (iCountCommands == 0) goto err_cmdline;

	return 0;

err_insuf_buf:
	LOGE(L"Error when parsing args: Insufficient Buffer");
	return ERROR_INSUFFICIENT_BUFFER;

err_get_exec_path:
	dwErrorCode = GetLastError();
	LOGE(L"Error when parsing args: SearchPath() Failed: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;

err_cmdline:
	dwErrorCode = GetLastError();
	LOGE(L"Error when parsing args: No command line provided");
	return ERROR_INVALID_COMMAND_LINE;
}
