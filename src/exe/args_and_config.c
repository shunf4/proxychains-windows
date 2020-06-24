// SPDX-License-Identifier: GPL-2.0-or-later
/* args_and_config.c
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
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#define PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#define _CRT_SECURE_NO_WARNINGS
#include "includes_win32.h"
#include <Shlwapi.h>
#include <Winsock2.h>
#include <Ws2TcpIp.h>
#include <wchar.h>
#include <inttypes.h>
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>
#include <ShlObj.h>

#include "defines_win32.h"
#include "log_win32.h"
#include "hookdll_win32.h"
#include "hookdll_util_win32.h"

#ifndef __CYGWIN__
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#define popen _popen
#endif

#define PXCH_CONFIG_PARSE_WHITE L" \n\t\r\v"
#define PXCH_CONFIG_PARSE_DIGIT L"0123456789"
#define PXCH_CONFIG_PARSE_HEX PXCH_CONFIG_PARSE_DIGIT L"abcdefABCDEF"
#define PXCH_CONFIG_PARSE_IP_PORT PXCH_CONFIG_PARSE_HEX L"[.:]"

#if defined(_M_X64) || defined(__x86_64__)
#define PXCH_FUNCTION_SUFFIX_ARCH X64
#else
#define PXCH_FUNCTION_SUFFIX_ARCH X86
#endif

#define ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, funcName, funcPtr, arch) (pPxchConfig)->FunctionPointers.fp##funcName##arch = (PXCH_UINT64)(uintptr_t)(funcPtr)
#define ASSIGN_FUNC_ADDR_WITH_ARCH_X(pPxchConfig, funcName, funcPtr, arch) ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, funcName, funcPtr, arch)
#define ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, funcName) ASSIGN_FUNC_ADDR_WITH_ARCH_X(pPxchConfig, funcName, &funcName, PXCH_FUNCTION_SUFFIX_ARCH)
#define ASSIGN_FUNC_ADDR(pPxchConfig, funcName, funcPtr) ASSIGN_FUNC_ADDR_WITH_ARCH_X(pPxchConfig, funcName, funcPtr, PXCH_FUNCTION_SUFFIX_ARCH)

#define PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, funcName) LOGD(L"fp" PREFIX_L(#funcName) L"X64 = %p", (pPxchConfig)->FunctionPointers.fp##funcName##X64);LOGD(L"fp" PREFIX_L(#funcName) L"X86 = %p", (pPxchConfig)->FunctionPointers.fp##funcName##X86)

#ifndef __CYGWIN__
#define wcsncasecmp _wcsnicmp
#endif

#define WSTR_EQUAL(str, strend, strLiteral) ((wcsncmp(str, strLiteral, _countof(strLiteral) - 1) == 0) ? (strend == str + _countof(strLiteral) - 1) : FALSE)
#define WSTR_EQUAL_I(str, strend, strLiteral) ((wcsncasecmp(str, strLiteral, _countof(strLiteral) - 1) == 0) ? (strend == str + _countof(strLiteral) - 1) : FALSE)

static const WCHAR* pszParseErrorMessage;

// impl: stdlib_config_reader.c
PXCH_UINT32 OpenConfigurationFile(PROXYCHAINS_CONFIG* pPxchConfig);
PXCH_UINT32 OpenHostsFile(const WCHAR* szHostsFilePath);
PXCH_UINT32 ConfigurationFileReadLine(unsigned long long* pullLineNum, wchar_t* chBuf, size_t cbBufSize);
PXCH_UINT32 HostsFileReadLine(unsigned long long* pullHostsLineNum, wchar_t* chBuf, size_t cbBufSize);
PXCH_UINT32 CloseConfigurationFile();
PXCH_UINT32 CloseHostsFile();
long ConfigurationTellPos();
void ConfigurationRewind();
long HostsTellPos();
void HostsRewind();

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

static inline BOOL CharInSet(const WCHAR* pStart, const WCHAR* pCharset)
{
	const WCHAR* pSet;
	for (pSet = pCharset; *pSet; pSet++) {
		if (*pStart == *pSet) return TRUE;
	}
	return FALSE;
}

static inline WCHAR* ConsumeStringUntilSet(WCHAR* pStart, WCHAR* pEndOptional, const WCHAR* pCharset)
{
	WCHAR* p;
	const WCHAR* pSet;
	for (p = pStart; *p && (!pEndOptional || p <= pEndOptional); p++) {
		for (pSet = pCharset; *pSet; pSet++) {
			if (*p == *pSet) return p;
		}
	}
	return p;
}

static inline WCHAR* ConsumeStringInSet(WCHAR* pStart, WCHAR* pEndOptional, const WCHAR* pCharset)
{
	WCHAR* p;
	const WCHAR* pSet;
	BOOL bContain;

	for (p = pStart; *p && (!pEndOptional || p <= pEndOptional); p++) {
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

static int StringToAddress(LPWSTR AddressString, LPSOCKADDR lpAddress, int iAddressLength)
{
	int iAddressLength2;

	ZeroMemory(lpAddress, iAddressLength);
	iAddressLength2 = iAddressLength;
	if (WSAStringToAddressW(AddressString, AF_INET, NULL, lpAddress, &iAddressLength2) == 0) {
		return 0;
	}

	ZeroMemory(lpAddress, iAddressLength);
	iAddressLength2 = iAddressLength;

	if (WSAStringToAddressW(AddressString, AF_INET6, NULL, lpAddress, &iAddressLength2) == 0) {
		return 0;
	}

	return WSAHOST_NOT_FOUND;
}

static int OptionGetNumberValue(long* plNum, const WCHAR* pStart, const WCHAR* pEndOptional, long lRangeMin, long lRangeMax, BOOL bAllowTrailingWhite)
{
	const WCHAR* pAfterNumber;
	const WCHAR* pAfterWhite;
	long lResult;

	pAfterNumber = ConsumeStringInSet((WCHAR*)pStart, (WCHAR*)pEndOptional, PXCH_CONFIG_PARSE_DIGIT);
	if (pAfterNumber == pStart) {
		pszParseErrorMessage = L"No number value";
		return -1;
	}

	pAfterWhite = ConsumeStringInSet((WCHAR*)pAfterNumber, (WCHAR*)pEndOptional, PXCH_CONFIG_PARSE_WHITE);

	if (pEndOptional != NULL) {
		if ((!bAllowTrailingWhite && pEndOptional != pAfterNumber) || !(pEndOptional >= pAfterNumber && pEndOptional <= pAfterWhite)) {
			pszParseErrorMessage = L"Extra character after number value";
			return -1;
		}
	} else {
		if ((!bAllowTrailingWhite && *pAfterNumber != '\0') || (!CharInSet(pAfterWhite, L"#\n") && *pAfterWhite != L'\0')) {
			pszParseErrorMessage = L"Extra character after number value";
			return -1;
		}
	}

	lResult = wcstol(pStart, NULL, 10);
	if (lResult < lRangeMin || lResult > lRangeMax) {
		pszParseErrorMessage = L"Number out of range";
		return -1;
	}

	*plNum = lResult;
	return 0;
}

static int OptionGetStringValue(const WCHAR** ppEnd, const WCHAR* pStart, const WCHAR* pEndOptional, BOOL bAllowTrailingWhite)
{
	const WCHAR* pAfterString;
	const WCHAR* pAfterWhite;

	while (1) {
		pAfterString = ConsumeStringUntilSet((WCHAR*)pStart, (WCHAR*)pEndOptional, PXCH_CONFIG_PARSE_WHITE);
		pAfterWhite = ConsumeStringInSet((WCHAR*)pAfterString, (WCHAR*)pEndOptional, PXCH_CONFIG_PARSE_WHITE);

		if (*pAfterWhite == L'\0' || pAfterWhite == pEndOptional) break;

		pStart = pAfterWhite;
	}

	if (pEndOptional != NULL) {
		if ((!bAllowTrailingWhite && pEndOptional != pAfterString) || !(pEndOptional >= pAfterString && pEndOptional <= pAfterWhite)) {
			pszParseErrorMessage = L"Extra character after string value";
			return -1;
		}
	} else {
		if ((!bAllowTrailingWhite && *pAfterString != '\0') || (!CharInSet(pAfterWhite, L"#\n") && *pAfterWhite != L'\0')) {
			pszParseErrorMessage = L"Extra character after string value";
			return -1;
		}
	}

	*ppEnd = pAfterString;
	return 0;
}

static int OptionGetIpPortValue(PXCH_IP_PORT* pIpPort, PXCH_UINT32* pdwPrefixLength, WCHAR* pStart, WCHAR* pEndOptional, BOOL bAllowCidr, BOOL bAllowTrailingWhite)
{
	WCHAR* pAfterIpPort;
	WCHAR* pAfterWhite;
	WCHAR* pStartPrefix;
	WCHAR* pAfterPrefix;
	WCHAR cSaved;
	int iResult;
	
	pAfterIpPort = ConsumeStringInSet(pStart, pEndOptional, PXCH_CONFIG_PARSE_IP_PORT);

	if (pAfterIpPort == pStart) {
		pszParseErrorMessage = L"No IP specified";
		return -1;
	}

	cSaved = *pAfterIpPort;
	*pAfterIpPort = L'\0';
	ZeroMemory(pIpPort, sizeof(PXCH_IP_PORT));
	iResult = StringToAddress(pStart, (LPSOCKADDR)pIpPort, sizeof(PXCH_IP_PORT));
	*pAfterIpPort = cSaved;
	if (iResult) {
		pszParseErrorMessage = L"Invalid IP address";
		return -1;
	}

	if (*pAfterIpPort == L'/') {
		PXCH_IP_PORT PrefixIpPort;
		long lPrefix = -1;

		if (!bAllowCidr) {
			pszParseErrorMessage = L"CIDR prefix not allowed here";
			return -1;
		}

		pStartPrefix = pAfterIpPort + 1;
		if (pEndOptional != NULL && pStartPrefix >= pEndOptional) {
			pszParseErrorMessage = L"Empty CIDR prefix";
			return -1;
		}

		pAfterPrefix = ConsumeStringInSet(pStartPrefix, pEndOptional, PXCH_CONFIG_PARSE_IP_PORT);
		if (pAfterPrefix == pStartPrefix) {
			pszParseErrorMessage = L"Invalid or empty CIDR prefix value";
			return -1;
		}

		if (OptionGetNumberValue(&lPrefix, pStartPrefix, pAfterPrefix, 0, 128, FALSE)) {
			cSaved = *pAfterPrefix;
			*pAfterPrefix = L'\0';
			ZeroMemory(&PrefixIpPort, sizeof(PXCH_IP_PORT));
			iResult = StringToAddress(pStartPrefix, (LPSOCKADDR)&PrefixIpPort, sizeof(PXCH_IP_PORT));
			*pAfterPrefix = cSaved;
			if (iResult) {
				pszParseErrorMessage = L"Invalid CIDR prefix";
				return -1;
			} else {
				PXCH_UINT32 dwIpv4;

				if (pIpPort->CommonHeader.wTag == PXCH_HOST_TYPE_IPV6) {
					pszParseErrorMessage = L"Subnet mask in dot-decimal style should not be used with IPv6 address!";
					return -1;
				}

				if (PrefixIpPort.CommonHeader.wTag != PXCH_HOST_TYPE_IPV4 || PrefixIpPort.CommonHeader.wPort != 0) {
					pszParseErrorMessage = L"Subnet mask can only be IPv4 without port";
					return -1;
				}

				CopyMemory(&dwIpv4, &((struct sockaddr_in*)&PrefixIpPort)->sin_addr, sizeof(((struct sockaddr_in*)&PrefixIpPort)->sin_addr));

				dwIpv4 = ntohl(dwIpv4);
				
				if (dwIpv4 == 0) {
					lPrefix = 0;
				} else {
					PXCH_UINT32 dwNeedle = 0x80000000;
					if (((~dwIpv4 + 1) & (~dwIpv4)) != 0) {
						pszParseErrorMessage = L"Invalid subnet mask";
						return -1;
					}

					for (lPrefix = 0; (dwNeedle & dwIpv4); dwNeedle >>= 1, lPrefix++)
						;
				}
			}
		} else {
			if (pIpPort->CommonHeader.wTag == PXCH_HOST_TYPE_IPV4 && lPrefix > 32) {
				pszParseErrorMessage = L"Prefix length exceeds 32 for an IPv4 address";
				return -1;
			}
		}

		*pdwPrefixLength = (PXCH_UINT32)lPrefix;
	} else {
		if (bAllowCidr) {
			switch (pIpPort->CommonHeader.wTag) {
			case PXCH_HOST_TYPE_IPV4:
				*pdwPrefixLength = 32;
				break;
			case PXCH_HOST_TYPE_IPV6:
				*pdwPrefixLength = 128;
				break;
			}
		}

		pAfterPrefix = pAfterIpPort;
	}

	pAfterWhite = ConsumeStringInSet(pAfterPrefix, pEndOptional, PXCH_CONFIG_PARSE_WHITE);
	if (pEndOptional != NULL) {
		if ((!bAllowTrailingWhite && pEndOptional != pAfterPrefix) || !(pEndOptional >= pAfterPrefix && pEndOptional <= pAfterWhite)) {
			pszParseErrorMessage = L"Unexpected character after CIDR";
			return -1;
		}
	} else {
		if ((!bAllowTrailingWhite && !CharInSet(pAfterPrefix, L"#\n") && *pAfterPrefix != L'\0') || (!CharInSet(pAfterWhite, L"#\n") && *pAfterWhite != L'\0')) {
			pszParseErrorMessage = L"Extra character after CIDR";
			return -1;
		}
	}

	return 0;
}

static int OptionGetNumberValueAfterOptionName(long* plNum, const WCHAR* pAfterOptionName, const WCHAR* pEndOptional, long lRangeMin, long lRangeMax)
{
	const WCHAR* pAfterWhiteAndEqual;
	
	pAfterWhiteAndEqual = ConsumeStringInSet((WCHAR*)pAfterOptionName, (WCHAR*)pEndOptional, PXCH_CONFIG_PARSE_WHITE L"=");
	if (pAfterWhiteAndEqual == pAfterOptionName) {
		pszParseErrorMessage = L"No white space or = before value";
		return -1;
	}

	return OptionGetNumberValue(plNum, pAfterWhiteAndEqual, pEndOptional, lRangeMin, lRangeMax, TRUE);
}

static int OptionGetStringValueAfterOptionName(const WCHAR** ppStart, const WCHAR** ppEnd, const WCHAR* pAfterOptionName, const WCHAR* pEndOptional)
{
	const WCHAR* pAfterWhiteAndEqual;
	
	pAfterWhiteAndEqual = ConsumeStringInSet((WCHAR*)pAfterOptionName, (WCHAR*)pEndOptional, PXCH_CONFIG_PARSE_WHITE L"=");
	if (pAfterWhiteAndEqual == pAfterOptionName) {
		pszParseErrorMessage = L"No white space or = before value";
		return -1;
	}

	*ppStart = pAfterWhiteAndEqual;
	return OptionGetStringValue(ppEnd, pAfterWhiteAndEqual, pEndOptional, TRUE);
}

static int OptionGetIpPortValueAfterOptionName(PXCH_IP_PORT* pIpPort, PXCH_UINT32* pdwPrefixLength, WCHAR* pAfterOptionName, WCHAR* pEndOptional, BOOL bAllowCidr, BOOL bAllowTrailingWhite)
{
	WCHAR* pAfterWhiteAndEqual;
	
	pAfterWhiteAndEqual = ConsumeStringInSet(pAfterOptionName, pEndOptional, PXCH_CONFIG_PARSE_WHITE L"=");
	if (pAfterWhiteAndEqual == pAfterOptionName) {
		pszParseErrorMessage = L"No white space or = before value";
		return -1;
	}

	return OptionGetIpPortValue(pIpPort, pdwPrefixLength, pAfterWhiteAndEqual, pEndOptional, bAllowCidr, bAllowTrailingWhite);
}

static int OptionParseRuleTarget(PXCH_RULE* pRule, WCHAR* sTargetStart)
{
	WCHAR* sTargetEnd = ConsumeStringUntilSet(sTargetStart, NULL, PXCH_CONFIG_PARSE_WHITE);
	WCHAR* pEnd = ConsumeStringInSet(sTargetEnd, NULL, PXCH_CONFIG_PARSE_WHITE);

	if (*pEnd != L'\0') {
		pszParseErrorMessage = L"Extra character after rule target";
		return -1;
	}

	if (WSTR_EQUAL_I(sTargetStart, sTargetEnd, L"PROXY")) {
		pRule->dwTarget = PXCH_RULE_TARGET_PROXY;
	} else if (WSTR_EQUAL_I(sTargetStart, sTargetEnd, L"DIRECT")) {
		pRule->dwTarget = PXCH_RULE_TARGET_DIRECT;
	} else if (WSTR_EQUAL_I(sTargetStart, sTargetEnd, L"BLOCK")) {
		pRule->dwTarget = PXCH_RULE_TARGET_BLOCK;
	} else {
		pszParseErrorMessage = L"Invalid rule target";
		return -1;
	}

	return 0;
}

static int OptionParseAdditionalHostnameRule(PXCH_RULE* pRule, WCHAR* sOptionNameEnd)
{
	WCHAR* sComma;
	WCHAR* sHostnameStart;
	WCHAR* sHostnameEnd;
	WCHAR* sTargetStart;
	long lPort;

	pRule->HostPort.wTag = PXCH_HOST_TYPE_HOSTNAME;

	sComma = ConsumeStringInSet(sOptionNameEnd, NULL, PXCH_CONFIG_PARSE_WHITE);
	if (*sComma != L',') {
		pszParseErrorMessage = L"No comma after additional rule option name";
		return -1;
	}
	sHostnameStart = ConsumeStringInSet(sComma + 1, NULL, PXCH_CONFIG_PARSE_WHITE);
	sHostnameEnd = ConsumeStringUntilSet(sHostnameStart, NULL, PXCH_CONFIG_PARSE_WHITE L",:");

	if (sHostnameStart == sHostnameEnd) {
		//pszParseErrorMessage = L"Empty match string";
		//return -1;
	}

	StringCchCopyNW(pRule->HostPort.HostnamePort.szValue, _countof(pRule->HostPort.HostnamePort.szValue), sHostnameStart, sHostnameEnd - sHostnameStart);

	sComma = ConsumeStringUntilSet(sHostnameEnd, NULL, L",");

	if (*sHostnameEnd == L':') {
		if (OptionGetNumberValue(&lPort, sHostnameEnd + 1, sComma, 1, 65535, TRUE)) return -1;
	} else {
		lPort = 0;
	}

	pRule->HostPort.HostnamePort.wPort = ntohs((PXCH_UINT16)lPort);

	if (*sComma != L',') {
		pszParseErrorMessage = L"No comma after additional rule hostname";
		return -1;
	}

	sTargetStart = ConsumeStringInSet(sComma + 1, NULL, PXCH_CONFIG_PARSE_WHITE);
	if (OptionParseRuleTarget(pRule, sTargetStart)) return -1;

	return 0;
}

void PrintConfiguration(PROXYCHAINS_CONFIG* pPxchConfig)
{
	DWORD dw;
	PXCH_RULE* arrRule;
	PXCH_PROXY_DATA* arrProxy;
	PXCH_HOSTS_ENTRY* arrHostsEntry;
	const WCHAR* pszTagDesc;
	const WCHAR* pszTargetDesc;

	(void)arrRule;
	(void)arrProxy;
	(void)arrHostsEntry;
	(void)pszTagDesc;
	(void)pszTargetDesc;

	LOGD(L"Configuration fixed part size: " WPRDW, (PXCH_UINT32)(sizeof(PROXYCHAINS_CONFIG)));
	LOGD(L"Configuration total size: " WPRDW, (PXCH_UINT32)(sizeof(PROXYCHAINS_CONFIG) + PXCH_CONFIG_EXTRA_SIZE(pPxchConfig)));
	
	LOGD(L"MasterProcessId: " WPRDW, pPxchConfig->dwMasterProcessId);
	LOGD(L"LogLevel: " WPRDW, pPxchConfig->dwLogLevel);
	LOGD(L"IpcPipeName: %ls", pPxchConfig->szIpcPipeName);
	LOGD(L"ConfigPath: %ls", pPxchConfig->szConfigPath);
	LOGD(L"HookDllPath: %ls", pPxchConfig->szHookDllPath);
	LOGD(L"MinHookDllPath: %ls", pPxchConfig->szMinHookDllPath);
	LOGD(L"HostsFilePath: %ls", pPxchConfig->szHostsFilePath);
	LOGD(L"CommandLine: %ls", pPxchConfig->szCommandLine);
	LOGD(L"FakeIpv4Range: %ls/" WPRDW, FormatHostPortToStr(&pPxchConfig->FakeIpv4Range, sizeof(PXCH_IP_ADDRESS)), pPxchConfig->dwFakeIpv4PrefixLength);
	LOGD(L"FakeIpv6Range: %ls/" WPRDW, FormatHostPortToStr(&pPxchConfig->FakeIpv6Range, sizeof(PXCH_IP_ADDRESS)), pPxchConfig->dwFakeIpv6PrefixLength);
	LOGD(L"ProxyConnectionTimeoutMillisecond: " WPRDW, pPxchConfig->dwProxyConnectionTimeoutMillisecond);
	LOGD(L"ProxyHandshakeTimeoutMillisecond: " WPRDW, pPxchConfig->dwProxyHandshakeTimeoutMillisecond);
	LOGD(L"WillUseFakeIpAsRemoteDns: " WPRDW, pPxchConfig->dwWillUseFakeIpAsRemoteDns);
	LOGD(L"WillUseUdpAssociateAsRemoteDns: " WPRDW, pPxchConfig->dwWillUseUdpAssociateAsRemoteDns);
	LOGD(L"WillDeleteFakeIpAfterChildProcessExits: " WPRDW, pPxchConfig->dwWillDeleteFakeIpAfterChildProcessExits);
	LOGD(L"WillUseFakeIpWhenHostnameNotMatched: " WPRDW, pPxchConfig->dwWillUseFakeIpWhenHostnameNotMatched);
	LOGD(L"WillMapResolvedIpToHost: " WPRDW, pPxchConfig->dwWillMapResolvedIpToHost);
	LOGD(L"WillLookupForHostByResolvedIp: " WPRDW, pPxchConfig->dwWillLookupForHostByResolvedIp);
	LOGD(L"WillResolveLocallyIfMatchHosts: " WPRDW, pPxchConfig->dwWillResolveLocallyIfMatchHosts);
	LOGD(L"WillFirstTunnelUseIpv4: " WPRDW, pPxchConfig->dwWillFirstTunnelUseIpv4);
	LOGD(L"WillFirstTunnelUseIpv6: " WPRDW, pPxchConfig->dwWillFirstTunnelUseIpv6);
	LOGD(L"WillGenFakeIpUsingHashedHostname: " WPRDW, pPxchConfig->dwWillGenFakeIpUsingHashedHostname);
	switch (pPxchConfig->dwDefaultTarget) {
		case PXCH_RULE_TARGET_BLOCK: pszTargetDesc = L"BLOCK"; break;
		case PXCH_RULE_TARGET_DIRECT: pszTargetDesc = L"DIRECT"; break;
		case PXCH_RULE_TARGET_PROXY: pszTargetDesc = L"PROXY"; break;
		default: pszTargetDesc = L"???"; break;
	}
	LOGD(L"DefaultTarget: %ls", pszTargetDesc);
	LOGD(L"sizeof(PROXYCHAINS_CONFIG): %lu", (unsigned long)(sizeof(PROXYCHAINS_CONFIG)));
	LOGD(L"");

	LOGD(L"[ProxyList] Offset: " WPRDW L", sizeof(): " WPRDW L", Length: " WPRDW, pPxchConfig->cbProxyListOffset, (DWORD)(sizeof(PXCH_PROXY_DATA)), pPxchConfig->dwProxyNum);
	arrProxy = PXCH_CONFIG_PROXY_ARR(pPxchConfig);
	for (dw = 0; dw < pPxchConfig->dwProxyNum; dw++) {
		switch (arrProxy[dw].dwTag) {
			case PXCH_PROXY_TYPE_INVALID: pszTagDesc = L"INVALID"; break;
			case PXCH_PROXY_TYPE_SOCKS5: pszTagDesc = L"SOCKS5"; break;
			case PXCH_PROXY_TYPE_DIRECT: pszTagDesc = L"DIRECT"; break;
			default: pszTagDesc = L"???"; break;
		}

		if (ProxyIsType(SOCKS5, arrProxy[dw])) {
			LOGD(L"[" WPRDW L"] <%ls> %ls(%d) " WPRS L" " WPRS L" %ls %ls", dw, pszTagDesc, FormatHostPortToStr(&arrProxy[dw].CommonHeader.HostPort, arrProxy[dw].CommonHeader.iAddrLen), arrProxy[dw].CommonHeader.iAddrLen, arrProxy[dw].CommonHeader.Ws2_32_ConnectFunctionName, arrProxy[dw].CommonHeader.Ws2_32_HandshakeFunctionName, arrProxy[dw].Socks5.szUsername, arrProxy[dw].Socks5.szPassword);
		}
	}
	LOGD(L"");

	LOGD(L"[RuleList] Offset: " WPRDW L", sizeof(): " WPRDW L", Length: " WPRDW, pPxchConfig->cbRuleListOffset, (DWORD)(sizeof(PXCH_RULE)), pPxchConfig->dwRuleNum);
	arrRule = PXCH_CONFIG_RULE_ARR(pPxchConfig);
	for (dw = 0; dw < pPxchConfig->dwRuleNum; dw++) {
		switch (arrRule[dw].dwTag) {
			case PXCH_RULE_TYPE_DOMAIN_KEYWORD: pszTagDesc = L"DOMAIN_KEYWORD"; break;
			case PXCH_RULE_TYPE_DOMAIN_SUFFIX: pszTagDesc = L"DOMAIN_SUFFIX"; break;
			case PXCH_RULE_TYPE_DOMAIN: pszTagDesc = L"DOMAIN"; break;
			case PXCH_RULE_TYPE_IP_CIDR: pszTagDesc = L"IP_CIDR"; break;
			case PXCH_RULE_TYPE_PORT: pszTagDesc = L"PORT"; break;
			case PXCH_RULE_TYPE_FINAL: pszTagDesc = L"FINAL"; break;
			case PXCH_RULE_TYPE_INVALID: pszTagDesc = L"INVALID"; break;
			default: pszTagDesc = L"???"; break;
		}

		switch (arrRule[dw].dwTarget) {
			case PXCH_RULE_TARGET_BLOCK: pszTargetDesc = L"BLOCK"; break;
			case PXCH_RULE_TARGET_DIRECT: pszTargetDesc = L"DIRECT"; break;
			case PXCH_RULE_TARGET_PROXY: pszTargetDesc = L"PROXY"; break;
			default: pszTargetDesc = L"???"; break;
		}

		LOGD(L"[" WPRDW L"] <%ls> %ls/" WPRDW L" -> %ls", dw, pszTagDesc, FormatHostPortToStr(&arrRule[dw].HostPort, sizeof(PXCH_IP_ADDRESS)), arrRule[dw].dwCidrPrefixLength, pszTargetDesc);
	}
	LOGD(L"");
	
	LOGD(L"[HostsEntry] Offset: " WPRDW L", sizeof(): " WPRDW L", Length: " WPRDW, pPxchConfig->cbHostsEntryListOffset, (DWORD)(sizeof(PXCH_HOSTS_ENTRY)), pPxchConfig->dwHostsEntryNum);
	arrHostsEntry = PXCH_CONFIG_HOSTS_ENTRY_ARR(pPxchConfig);
	for (dw = 0; dw < pPxchConfig->dwHostsEntryNum; dw++) {
		LOGD(L"[" WPRDW L"] %ls %ls", dw, arrHostsEntry[dw].Hostname.szValue, FormatHostPortToStr(&arrHostsEntry[dw].Ip, sizeof(PXCH_IP_ADDRESS)));
	}
	LOGD(L"");

	LOGD(L"(Deprecated)RemoteFuncX64 Offset: " WPRDW L", Size: " WPRDW, pPxchConfig->cbRemoteFuncX64Offset, pPxchConfig->cbRemoteFuncX64Size);
	LOGD(L"(Deprecated)RemoteFuncX86 Offset: " WPRDW L", Size: " WPRDW, pPxchConfig->cbRemoteFuncX86Offset, pPxchConfig->cbRemoteFuncX86Size);
	LOGD(L"PXCH_CONFIG_EXTRA_SIZE_G: " WPRDW, PXCH_CONFIG_EXTRA_SIZE_G);
}

DWORD LoadConfiguration(PROXYCHAINS_CONFIG** ppPxchConfig, PROXYCHAINS_CONFIG* pTempPxchConfig)
{
	DWORD dwLastError;
	WSADATA wsaData;
	DWORD dwRet;
	FILETIME ft;
	ULARGE_INTEGER uli;
	PROXYCHAINS_CONFIG* pPxchConfig;
	int iDummy;
	CHAR szHelperX64CommandLine[PXCH_MAX_HELPER_PATH_BUFSIZE];
	CHAR szHelperX86CommandLine[PXCH_MAX_HELPER_PATH_BUFSIZE];
	WCHAR szConfigurationLine[PXCH_MAX_CONFIGURATION_LINE_BUFSIZE];
	WCHAR szHostsLine[PXCH_MAX_HOSTS_LINE_BUFSIZE];
	unsigned long long ullLineNum;
	BOOL bIntoProxyList;
	DWORD dwRuleNum = 0;
	DWORD dwProxyNum = 0;
	DWORD dwHostsEntryNum = 0;
	DWORD dwProxyCounter = 0;
	DWORD dwRuleCounter = 0;
	DWORD dwHostsEntryCounter = 0;

	WSAStartup(MAKEWORD(2, 2), &wsaData);

	// Defaults
	pPxchConfig = pTempPxchConfig;
	pPxchConfig->dwMasterProcessId = GetCurrentProcessId();

	GetSystemTimeAsFileTime(&ft);
	uli.HighPart = ft.dwHighDateTime;
	uli.LowPart = ft.dwLowDateTime;
	StringCchPrintfW(pPxchConfig->szIpcPipeName, _countof(pPxchConfig->szIpcPipeName), L"\\\\.\\pipe\\proxychains_" WPRDW L"_%" PREFIX_L(PRIu64) L"", GetCurrentProcessId(), uli.QuadPart);

	dwRet = GetModuleFileNameW(NULL, pPxchConfig->szHookDllPathX64, PXCH_MAX_DLL_PATH_BUFSIZE);
	if (dwRet == 0) goto err_insuf_buf;
	if (dwRet == PXCH_MAX_DLL_PATH_BUFSIZE) goto err_insuf_buf;

	if (!PathRemoveFileSpecW(pPxchConfig->szHookDllPathX64)) goto err_insuf_buf;

	if (FAILED(StringCchCatW(pPxchConfig->szHookDllPathX64, PXCH_MAX_DLL_PATH_BUFSIZE, L"\\"))) goto err_insuf_buf;

	if (FAILED(StringCchCopyW(pPxchConfig->szHookDllPathX86, PXCH_MAX_DLL_PATH_BUFSIZE, pPxchConfig->szHookDllPathX64))) goto err_insuf_buf;
	if (FAILED(StringCchCopyW(pPxchConfig->szMinHookDllPathX64, PXCH_MAX_DLL_PATH_BUFSIZE, pPxchConfig->szHookDllPathX64))) goto err_insuf_buf;
	if (FAILED(StringCchCopyW(pPxchConfig->szMinHookDllPathX86, PXCH_MAX_DLL_PATH_BUFSIZE, pPxchConfig->szHookDllPathX64))) goto err_insuf_buf;
	if (FAILED(StringCchPrintfA(szHelperX64CommandLine, PXCH_MAX_HELPER_PATH_BUFSIZE, "%ls", pPxchConfig->szHookDllPathX64))) goto err_insuf_buf;
	if (FAILED(StringCchPrintfA(szHelperX86CommandLine, PXCH_MAX_HELPER_PATH_BUFSIZE, "%ls", pPxchConfig->szHookDllPathX64))) goto err_insuf_buf;

#ifdef __CYGWIN__
	{
		CHAR* pChar;
		for (pChar = szHelperX64CommandLine; *pChar; pChar++) if (*pChar == '\\') *pChar = '/';
		for (pChar = szHelperX86CommandLine; *pChar; pChar++) if (*pChar == '\\') *pChar = '/';
	}
#endif

	if (FAILED(StringCchCatW(pPxchConfig->szHookDllPathX64, PXCH_MAX_DLL_PATH_BUFSIZE, g_szHookDllFileNameX64))) goto err_insuf_buf;
	if (FAILED(StringCchCatW(pPxchConfig->szHookDllPathX86, PXCH_MAX_DLL_PATH_BUFSIZE, g_szHookDllFileNameX86))) goto err_insuf_buf;
	if (FAILED(StringCchCatW(pPxchConfig->szMinHookDllPathX64, PXCH_MAX_DLL_PATH_BUFSIZE, g_szMinHookDllFileNameX64))) goto err_insuf_buf;
	if (FAILED(StringCchCatW(pPxchConfig->szMinHookDllPathX86, PXCH_MAX_DLL_PATH_BUFSIZE, g_szMinHookDllFileNameX86))) goto err_insuf_buf;
	if (FAILED(StringCchCatA(szHelperX64CommandLine, PXCH_MAX_HELPER_PATH_BUFSIZE, PXCH_HELPER_X64_COMMANDLINE_SUFFIX))) goto err_insuf_buf;
	if (FAILED(StringCchCatA(szHelperX86CommandLine, PXCH_MAX_HELPER_PATH_BUFSIZE, PXCH_HELPER_X86_COMMANDLINE_SUFFIX))) goto err_insuf_buf;

#if defined(_M_X64) || defined(__x86_64__)
	if (!PathFileExistsW(pPxchConfig->szHookDllPathX64)) goto err_dll_not_exist;
#else
	if (!PathFileExistsW(pPxchConfig->szHookDllPathX86)) goto err_dll_not_exist;
#endif
	if (!PathFileExistsW(pPxchConfig->szMinHookDllPathX64)) StringCchCopyW(pPxchConfig->szMinHookDllPathX64, PXCH_MAX_DLL_PATH_BUFSIZE, g_szMinHookDllFileNameX64);
	if (!PathFileExistsW(pPxchConfig->szMinHookDllPathX86)) StringCchCopyW(pPxchConfig->szMinHookDllPathX86, PXCH_MAX_DLL_PATH_BUFSIZE, g_szMinHookDllFileNameX86);

#ifdef __CYGWIN__
	StringCchCopyW(pPxchConfig->szHostsFilePath, _countof(pPxchConfig->szHostsFilePath), L"/etc/hosts");
#else
	SHGetFolderPathAndSubDirW(NULL, CSIDL_SYSTEM, NULL, 0, L"drivers", pPxchConfig->szHostsFilePath);
	if (FAILED(StringCchCatW(pPxchConfig->szHostsFilePath, _countof(pPxchConfig->szHostsFilePath), L"\\etc\\hosts"))) goto err_general;
#endif

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

	pPxchConfig->dwDefaultTarget = PXCH_RULE_TARGET_PROXY;

	pPxchConfig->dwWillDeleteFakeIpAfterChildProcessExits = FALSE;
	pPxchConfig->dwWillUseFakeIpWhenHostnameNotMatched = TRUE;
	pPxchConfig->dwWillMapResolvedIpToHost = FALSE;
	pPxchConfig->dwWillLookupForHostByResolvedIp = FALSE;
	pPxchConfig->dwWillResolveLocallyIfMatchHosts = TRUE;
	pPxchConfig->dwWillUseUdpAssociateAsRemoteDns = FALSE;
	pPxchConfig->dwWillUseFakeIpAsRemoteDns = FALSE;
	pPxchConfig->dwWillGenFakeIpUsingHashedHostname = TRUE;

	// Parse configuration file

	if ((dwLastError = OpenConfigurationFile(pTempPxchConfig)) != NO_ERROR) goto err_general;

	bIntoProxyList = FALSE;
	while ((dwLastError = ConfigurationFileReadLine(&ullLineNum, szConfigurationLine, _countof(szConfigurationLine))) == NO_ERROR) {
		WCHAR* sOption;
		WCHAR* sOptionNameEnd;
		long lValue;

		if (ullLineNum >= (1 << 31)) goto err_too_large;

		sOption = ConsumeStringInSet(szConfigurationLine, NULL, PXCH_CONFIG_PARSE_WHITE);
		if (*sOption == L'#' || *sOption == L'\0') continue;
		sOptionNameEnd = ConsumeStringUntilSet(sOption, NULL, PXCH_CONFIG_PARSE_WHITE L",#");

		if (WSTR_EQUAL(sOption, sOptionNameEnd, L"[ProxyList]")) {
			bIntoProxyList = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"socks5")) {
			dwProxyNum++;
		} else if (bIntoProxyList) {
			LOGE(L"Config line %llu: Unknown proxy: %.*ls", ullLineNum, sOptionNameEnd - sOption, sOption);
			goto err_invalid_config;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"strict_chain")) {
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"random_chain")) {
			pszParseErrorMessage = L"random_chain is not supported!";
			goto err_invalid_config_with_msg;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"chain_len")) {
			pszParseErrorMessage = L"chain_len is not supported!";
			goto err_invalid_config_with_msg;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"quiet_mode")) {
			if (!pTempPxchConfig->dwLogLevelSetByArg) {
				LOGD(L"Queit mode enabled in configuration file");
				pTempPxchConfig->dwLogLevel = PXCH_LOG_LEVEL_ERROR;
			}
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"log_level")) {
			if (!pTempPxchConfig->dwLogLevelSetByArg) {
				if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 0, 1000) == -1) goto err_invalid_config_with_msg;
				pPxchConfig->dwLogLevel = (DWORD)lValue;
			}
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"proxy_dns")) {
			pTempPxchConfig->dwWillUseFakeIpAsRemoteDns = TRUE;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"proxy_dns_udp_associate")) {
			pszParseErrorMessage = L"proxy_dns_udp_associate is not supported!";
			goto err_invalid_config_with_msg;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"remote_dns_subnet")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 0, 255) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwFakeIpv4PrefixLength = 8;
			ZeroMemory(&pPxchConfig->FakeIpv4Range, sizeof(pPxchConfig->FakeIpv4Range));
			pPxchConfig->FakeIpv4Range.CommonHeader.wTag = PXCH_HOST_TYPE_IPV4;
			((unsigned char*)&((struct sockaddr_in*)&pPxchConfig->FakeIpv4Range)->sin_addr)[0] = (unsigned char)lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"remote_dns_subnet_cidr_v4")) {
			if (OptionGetIpPortValueAfterOptionName((PXCH_IP_PORT*)&pPxchConfig->FakeIpv4Range, &pPxchConfig->dwFakeIpv4PrefixLength, sOptionNameEnd, NULL, TRUE, TRUE)) goto err_invalid_config_with_msg;
			if (pPxchConfig->FakeIpv4Range.CommonHeader.wTag != PXCH_HOST_TYPE_IPV4) {
				pszParseErrorMessage = L"Remote DNS subnet IPv6 CIDR block provided to remote_dns_subnet_cidr_v4!";
				goto err_invalid_config_with_msg;
			}
			if (pPxchConfig->dwFakeIpv4PrefixLength >= 31) {
				pszParseErrorMessage = L"Remote DNS subnet IPv4 CIDR prefix length should not exceed 30!";
				goto err_invalid_config_with_msg;
			}
			if (pPxchConfig->FakeIpv4Range.CommonHeader.wPort != 0) {
				pszParseErrorMessage = L"Remote DNS subnet CIDR block should not have a port number!";
				goto err_invalid_config_with_msg;
			}
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"remote_dns_subnet_cidr_v6")) {
			if (OptionGetIpPortValueAfterOptionName((PXCH_IP_PORT*)&pPxchConfig->FakeIpv6Range, &pPxchConfig->dwFakeIpv6PrefixLength, sOptionNameEnd, NULL, TRUE, TRUE)) goto err_invalid_config_with_msg;
			if (pPxchConfig->FakeIpv6Range.CommonHeader.wTag != PXCH_HOST_TYPE_IPV6) {
				pszParseErrorMessage = L"Remote DNS subnet IPv4 CIDR block provided to remote_dns_subnet_cidr_v6!";
				goto err_invalid_config_with_msg;
			}
			if (pPxchConfig->dwFakeIpv6PrefixLength >= 127) {
				pszParseErrorMessage = L"Remote DNS subnet IPv6 CIDR prefix length should not exceed 126!";
				goto err_invalid_config_with_msg;
			}
			if (pPxchConfig->FakeIpv6Range.CommonHeader.wPort != 0) {
				pszParseErrorMessage = L"Remote DNS subnet CIDR block should not have a port number!";
				goto err_invalid_config_with_msg;
			}
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"tcp_read_time_out")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 1, LONG_MAX) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwProxyHandshakeTimeoutMillisecond = lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"tcp_connect_time_out")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 1, LONG_MAX) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwProxyConnectionTimeoutMillisecond = lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"localnet")) {
			dwRuleNum++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN-KEYWORD")) {
			dwRuleNum++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN-SUFFIX")) {
			dwRuleNum++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN-FULL") || WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN")) {
			dwRuleNum++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"IP-CIDR")) {
			dwRuleNum++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"PORT")) {
			dwRuleNum++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"FINAL")) {
			dwRuleNum++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"delete_fake_ip_after_child_exits")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 0, 1) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwWillDeleteFakeIpAfterChildProcessExits = lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"use_fake_ip_when_hostname_not_matched")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 0, 1) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwWillUseFakeIpWhenHostnameNotMatched = lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"map_resolved_ip_to_host")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 0, 1) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwWillMapResolvedIpToHost = lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"search_for_host_by_resolved_ip")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 0, 1) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwWillLookupForHostByResolvedIp = lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"resolve_locally_if_match_hosts")
			|| WSTR_EQUAL(sOption, sOptionNameEnd, L"force_resolve_by_hosts_file")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 0, 1) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwWillResolveLocallyIfMatchHosts = lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"first_tunnel_uses_ipv4")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 0, 1) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwWillFirstTunnelUseIpv4 = lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"first_tunnel_uses_ipv6")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 0, 1) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwWillFirstTunnelUseIpv6 = lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"gen_fake_ip_using_hashed_hostname")) {
			if (OptionGetNumberValueAfterOptionName(&lValue, sOptionNameEnd, NULL, 0, 1) == -1) goto err_invalid_config_with_msg;
			pPxchConfig->dwWillGenFakeIpUsingHashedHostname = lValue;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"custom_hosts_file_path")) {
			const WCHAR* pPathStart;
			const WCHAR* pPathEnd;
			if (OptionGetStringValueAfterOptionName(&pPathStart, &pPathEnd, sOptionNameEnd, NULL) == -1) goto err_invalid_config_with_msg;
			if (FAILED(StringCchCopyNW(pPxchConfig->szHostsFilePath, _countof(pPxchConfig->szHostsFilePath), pPathStart, pPathEnd - pPathStart))) goto err_insuf_buf;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"default_target")) {
			const WCHAR* pTargetStart;
			const WCHAR* pTargetEnd;
			if (OptionGetStringValueAfterOptionName(&pTargetStart, &pTargetEnd, sOptionNameEnd, NULL) == -1) goto err_invalid_config_with_msg;
			if (WSTR_EQUAL_I(pTargetStart, pTargetEnd, L"PROXY")) {
				pPxchConfig->dwDefaultTarget = PXCH_RULE_TARGET_PROXY;
			} else if (WSTR_EQUAL_I(pTargetStart, pTargetEnd, L"DIRECT")) {
				pPxchConfig->dwDefaultTarget = PXCH_RULE_TARGET_DIRECT;
			} else if (WSTR_EQUAL_I(pTargetStart, pTargetEnd, L"BLOCK")) {
				pPxchConfig->dwDefaultTarget = PXCH_RULE_TARGET_BLOCK;
			} else {
				pszParseErrorMessage = L"Invalid default target";
				goto err_invalid_config_with_msg;
			}
		} else {
			LOGE(L"Config line %llu: Unknown option: %.*ls", ullLineNum, sOptionNameEnd - sOption, sOption);
			goto err_invalid_config;
		}
	}

	if (dwLastError != ERROR_END_OF_MEDIA) goto err_read_config;

	// Parse hosts file

	if ((dwLastError = OpenHostsFile(pPxchConfig->szHostsFilePath)) != NO_ERROR) goto err_general;

	while ((dwLastError = HostsFileReadLine(&ullLineNum, szHostsLine, _countof(szHostsLine))) == NO_ERROR) {
		WCHAR* sLineStart;
		WCHAR* sIpEnd;
		WCHAR* sHostnameStart;
		WCHAR* sHostnameEnd;

		if (ullLineNum >= (1 << 31)) goto err_too_large;

		sLineStart = ConsumeStringInSet(szHostsLine, NULL, PXCH_CONFIG_PARSE_WHITE);
		if (*sLineStart == L'#' || *sLineStart == L'\0') continue;

		sIpEnd = ConsumeStringInSet(sLineStart, NULL, PXCH_CONFIG_PARSE_IP_PORT);
	
		sHostnameStart = ConsumeStringInSet(sIpEnd, NULL, PXCH_CONFIG_PARSE_WHITE);

		if (sHostnameStart == sIpEnd) {
			pszParseErrorMessage = L"No delimiter between IP and hostname";
			goto err_invalid_hosts_with_msg;
		}

		sHostnameEnd = ConsumeStringUntilSet(sHostnameStart, NULL, PXCH_CONFIG_PARSE_WHITE);
		if (sHostnameStart == sHostnameEnd) {
			pszParseErrorMessage = L"Empty hostname";
			goto err_invalid_hosts_with_msg;
		}

		while (1) {
			dwHostsEntryNum++;
		
			sHostnameStart = ConsumeStringInSet(sHostnameEnd, NULL, PXCH_CONFIG_PARSE_WHITE);
			sHostnameEnd = ConsumeStringUntilSet(sHostnameStart, NULL, PXCH_CONFIG_PARSE_WHITE);
			if (sHostnameStart == sHostnameEnd) {
				break;
			}
		}
	}

	if (dwLastError != ERROR_END_OF_MEDIA) goto err_read_hosts;

	// Deprecated
	pPxchConfig->cbRemoteFuncX64Size = 0;
	pPxchConfig->cbRemoteFuncX86Size = 0;

	// Allocate space
	pPxchConfig = *ppPxchConfig = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PROXYCHAINS_CONFIG) + PXCH_CONFIG_EXTRA_SIZE_BY_N(dwProxyNum, dwRuleNum, dwHostsEntryNum, pPxchConfig->cbRemoteFuncX64Size, pPxchConfig->cbRemoteFuncX86Size));

	CopyMemory(pPxchConfig, pTempPxchConfig, sizeof(PROXYCHAINS_CONFIG));

	pPxchConfig->dwProxyNum = dwProxyNum;
	pPxchConfig->cbProxyListOffset = sizeof(PROXYCHAINS_CONFIG);
	pPxchConfig->dwRuleNum = dwRuleNum;
	pPxchConfig->cbRuleListOffset = sizeof(PROXYCHAINS_CONFIG) + (sizeof(PXCH_PROXY_DATA) * pPxchConfig->dwProxyNum);
	pPxchConfig->dwHostsEntryNum = dwHostsEntryNum;
	pPxchConfig->cbHostsEntryListOffset = sizeof(PROXYCHAINS_CONFIG) + (sizeof(PXCH_PROXY_DATA) * pPxchConfig->dwProxyNum) + (sizeof(PXCH_RULE) * pPxchConfig->dwRuleNum);
	// Deprecated
	pPxchConfig->cbRemoteFuncX64Offset = pPxchConfig->cbHostsEntryListOffset + (sizeof(PXCH_HOSTS_ENTRY) * pPxchConfig->dwHostsEntryNum);
	pPxchConfig->cbRemoteFuncX86Offset = pPxchConfig->cbRemoteFuncX64Offset + pPxchConfig->cbRemoteFuncX64Size;

	ConfigurationRewind();

	// Parse configuration file again

	while ((dwLastError = ConfigurationFileReadLine(&ullLineNum, szConfigurationLine, _countof(szConfigurationLine))) == NO_ERROR) {
		WCHAR* sOption;
		WCHAR* sOptionNameEnd;

		if (ullLineNum >= (1 << 31)) goto err_too_large;

		sOption = ConsumeStringInSet(szConfigurationLine, NULL, PXCH_CONFIG_PARSE_WHITE);
		if (*sOption == L'#' || *sOption == L'\0') continue;
		sOptionNameEnd = ConsumeStringUntilSet(sOption, NULL, PXCH_CONFIG_PARSE_WHITE L",#");

		if (WSTR_EQUAL(sOption, sOptionNameEnd, L"socks5")) {
			WCHAR* sHostStart;
			WCHAR* sHostEnd;
			WCHAR* sPortStart;
			WCHAR* sPortEnd;
			WCHAR* sUserPassStart;
			WCHAR* sUserPassEnd;
			long lPort;

			PXCH_PROXY_SOCKS5_DATA* pSocks5 = &PXCH_CONFIG_PROXY_ARR(pPxchConfig)[dwProxyCounter].Socks5;

			pSocks5->dwTag = PXCH_PROXY_TYPE_SOCKS5;

			sHostStart = ConsumeStringInSet(sOptionNameEnd, NULL, PXCH_CONFIG_PARSE_WHITE);
			sHostEnd = ConsumeStringUntilSet(sHostStart, NULL, PXCH_CONFIG_PARSE_WHITE);

			if (sHostStart == sHostEnd) {
				pszParseErrorMessage = L"SOCKS5 server host missing";
				goto err_invalid_config_with_msg;
			}

			if (OptionGetIpPortValue((PXCH_IP_PORT*)&pSocks5->HostPort, NULL, sHostStart, sHostEnd, FALSE, TRUE) == 0) {
				if (PXCH_CONFIG_PROXY_ARR(pPxchConfig)[dwProxyCounter].Socks5.HostPort.CommonHeader.wPort != 0) {
					pszParseErrorMessage = L"SOCKS5 server host address should not have port (place port number after the address and separate them with whitespaces)";
					goto err_invalid_config_with_msg;
				}
			} else {
				pSocks5->HostPort.HostnamePort.wTag = PXCH_HOST_TYPE_HOSTNAME;
				StringCchCopyNW(pSocks5->HostPort.HostnamePort.szValue, _countof(pSocks5->HostPort.HostnamePort.szValue), sHostStart, sHostEnd - sHostStart);
			}

			sPortStart = ConsumeStringInSet(sHostEnd, NULL, PXCH_CONFIG_PARSE_WHITE);
			sPortEnd = ConsumeStringUntilSet(sPortStart, NULL, PXCH_CONFIG_PARSE_WHITE);

			if (sPortStart == sPortEnd) {
				pszParseErrorMessage = L"SOCKS5 server port missing";
				goto err_invalid_config_with_msg;
			}

			if (OptionGetNumberValue(&lPort, sPortStart, sPortEnd, 1, 65535, TRUE)) {
				goto err_invalid_config_with_msg;
			}

			pSocks5->HostPort.CommonHeader.wPort = ntohs((PXCH_UINT16)lPort);

			sUserPassStart = ConsumeStringInSet(sPortEnd, NULL, PXCH_CONFIG_PARSE_WHITE);
			sUserPassEnd = ConsumeStringUntilSet(sUserPassStart, NULL, PXCH_CONFIG_PARSE_WHITE);

			if (*sUserPassStart == L'\0' || sUserPassStart == sUserPassEnd) goto socks5_end;

			StringCchPrintfA(pSocks5->szUsername, _countof(pSocks5->szUsername), "%.*ls", sUserPassEnd - sUserPassStart, sUserPassStart);

			sUserPassStart = ConsumeStringInSet(sUserPassEnd, NULL, PXCH_CONFIG_PARSE_WHITE);
			sUserPassEnd = ConsumeStringUntilSet(sUserPassStart, NULL, PXCH_CONFIG_PARSE_WHITE);
			if (*sUserPassStart == L'\0' || sUserPassStart == sUserPassEnd) {
				pszParseErrorMessage = L"SOCKS5 password missing";
				goto err_invalid_config_with_msg;
			}

			StringCchPrintfA(pSocks5->szPassword, _countof(pSocks5->szPassword), "%.*ls", sUserPassEnd - sUserPassStart, sUserPassStart);
				
			if (*ConsumeStringInSet(sUserPassEnd, NULL, PXCH_CONFIG_PARSE_WHITE) != L'\0') {
				pszParseErrorMessage = L"Extra character after socks5 server definition";
				goto err_invalid_config_with_msg;
			}

		socks5_end:
			StringCchCopyA(pSocks5->Ws2_32_ConnectFunctionName, _countof(pSocks5->Ws2_32_ConnectFunctionName), "Ws2_32_Socks5Connect");
			StringCchCopyA(pSocks5->Ws2_32_HandshakeFunctionName, _countof(pSocks5->Ws2_32_HandshakeFunctionName), "Ws2_32_Socks5Handshake");
			pSocks5->iAddrLen = sizeof(PXCH_HOST_PORT);
			dwProxyCounter++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"localnet")) {
			PXCH_RULE* pRule = &PXCH_CONFIG_RULE_ARR(pPxchConfig)[dwRuleCounter];
			if (OptionGetIpPortValueAfterOptionName(&pRule->HostPort.IpPort, &pRule->dwCidrPrefixLength, sOptionNameEnd, NULL, TRUE, TRUE)) goto err_invalid_config_with_msg;
			pRule->dwTag = PXCH_RULE_TYPE_IP_CIDR;
			pRule->dwTarget = PXCH_RULE_TARGET_DIRECT;
			dwRuleCounter++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN-KEYWORD")) {
			PXCH_RULE* pRule = &PXCH_CONFIG_RULE_ARR(pPxchConfig)[dwRuleCounter];
			pRule->dwTag = PXCH_RULE_TYPE_DOMAIN_KEYWORD;
			if (OptionParseAdditionalHostnameRule(pRule, sOptionNameEnd)) goto err_invalid_config_with_msg;
			dwRuleCounter++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN-SUFFIX")) {
			PXCH_RULE* pRule = &PXCH_CONFIG_RULE_ARR(pPxchConfig)[dwRuleCounter];
			pRule->dwTag = PXCH_RULE_TYPE_DOMAIN_SUFFIX;
			if (OptionParseAdditionalHostnameRule(pRule, sOptionNameEnd)) goto err_invalid_config_with_msg;
			dwRuleCounter++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN-FULL") || WSTR_EQUAL(sOption, sOptionNameEnd, L"DOMAIN")) {
			PXCH_RULE* pRule = &PXCH_CONFIG_RULE_ARR(pPxchConfig)[dwRuleCounter];
			pRule->dwTag = PXCH_RULE_TYPE_DOMAIN;
			if (OptionParseAdditionalHostnameRule(pRule, sOptionNameEnd)) goto err_invalid_config_with_msg;
			dwRuleCounter++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"IP-CIDR")) {
			WCHAR* sComma;
			WCHAR* sCidrStart;
			WCHAR* sCidrEnd;
			WCHAR* sTargetStart;
			PXCH_RULE* pRule = &PXCH_CONFIG_RULE_ARR(pPxchConfig)[dwRuleCounter];

			pRule->dwTag = PXCH_RULE_TYPE_IP_CIDR;

			sComma = ConsumeStringInSet(sOptionNameEnd, NULL, PXCH_CONFIG_PARSE_WHITE);
			if (*sComma != L',') {
				pszParseErrorMessage = L"No comma after additional rule option name";
				goto err_invalid_config_with_msg;
			}
			sCidrStart = ConsumeStringInSet(sComma + 1, NULL, PXCH_CONFIG_PARSE_WHITE);
			sCidrEnd = ConsumeStringUntilSet(sCidrStart, NULL, PXCH_CONFIG_PARSE_WHITE L",");

			if (sCidrStart == sCidrEnd) {
				pszParseErrorMessage = L"Empty CIDR string";
				goto err_invalid_config_with_msg;
			}

			if (OptionGetIpPortValue(&pRule->HostPort.IpPort, &pRule->dwCidrPrefixLength, sCidrStart, sCidrEnd, TRUE, TRUE)) goto err_invalid_config_with_msg;

			sComma = ConsumeStringUntilSet(sCidrEnd, NULL, L",");

			if (*sComma != L',') {
				pszParseErrorMessage = L"No comma after additional rule CIDR";
				goto err_invalid_config_with_msg;
			}

			sTargetStart = ConsumeStringInSet(sComma + 1, NULL, PXCH_CONFIG_PARSE_WHITE);
			if (OptionParseRuleTarget(pRule, sTargetStart)) goto err_invalid_config_with_msg;
		
			dwRuleCounter++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"PORT")) {
			WCHAR* sComma;
			WCHAR* sPortStart;
			WCHAR* sPortEnd;
			WCHAR* sTargetStart;
			long lPort;
			PXCH_RULE* pRule = &PXCH_CONFIG_RULE_ARR(pPxchConfig)[dwRuleCounter];

			pRule->dwTag = PXCH_RULE_TYPE_PORT;

			sComma = ConsumeStringInSet(sOptionNameEnd, NULL, PXCH_CONFIG_PARSE_WHITE);
			if (*sComma != L',') {
				pszParseErrorMessage = L"No comma after additional rule option name";
				goto err_invalid_config_with_msg;
			}
			sPortStart = ConsumeStringInSet(sComma + 1, NULL, PXCH_CONFIG_PARSE_WHITE);
			sPortEnd = ConsumeStringUntilSet(sPortStart, NULL, PXCH_CONFIG_PARSE_WHITE L",");

			if (sPortStart == sPortEnd) {
				pszParseErrorMessage = L"Empty port string";
				goto err_invalid_config_with_msg;
			}

			if (OptionGetNumberValue(&lPort, sPortStart, sPortEnd, 1, 65535, TRUE)) goto err_invalid_config_with_msg;
			pRule->HostPort.HostnamePort.wTag = PXCH_HOST_TYPE_HOSTNAME;
			pRule->HostPort.HostnamePort.szValue[0] = L'*';
			pRule->HostPort.HostnamePort.szValue[1] = L'\0';
			pRule->HostPort.HostnamePort.wPort = ntohs((PXCH_UINT16)lPort);

			sComma = ConsumeStringUntilSet(sPortEnd, NULL, L",");

			if (*sComma != L',') {
				pszParseErrorMessage = L"No comma after additional rule port";
				goto err_invalid_config_with_msg;
			}

			sTargetStart = ConsumeStringInSet(sComma + 1, NULL, PXCH_CONFIG_PARSE_WHITE);
			if (OptionParseRuleTarget(pRule, sTargetStart)) goto err_invalid_config_with_msg;

			dwRuleCounter++;
		} else if (WSTR_EQUAL(sOption, sOptionNameEnd, L"FINAL")) {
			WCHAR* sComma;
			WCHAR* sTargetStart;
			PXCH_RULE* pRule = &PXCH_CONFIG_RULE_ARR(pPxchConfig)[dwRuleCounter];

			pRule->dwTag = PXCH_RULE_TYPE_FINAL;

			sComma = ConsumeStringInSet(sOptionNameEnd, NULL, PXCH_CONFIG_PARSE_WHITE);
			if (*sComma != L',') {
				pszParseErrorMessage = L"No comma after additional rule option name";
				goto err_invalid_config_with_msg;
			}

			sTargetStart = ConsumeStringInSet(sComma + 1, NULL, PXCH_CONFIG_PARSE_WHITE);
			if (OptionParseRuleTarget(pRule, sTargetStart)) goto err_invalid_config_with_msg;

			dwRuleCounter++;
		}
	}

	if (dwLastError != ERROR_END_OF_MEDIA) goto err_read_config;

	// Parse hosts file again
	HostsRewind();

	while ((dwLastError = HostsFileReadLine(&ullLineNum, szHostsLine, _countof(szHostsLine))) == NO_ERROR) {
		WCHAR* sLineStart;
		WCHAR* sIpEnd;
		WCHAR* sHostnameStart;
		WCHAR* sHostnameEnd;
		PXCH_HOSTS_ENTRY* pHostsEntry;
		PXCH_IP_ADDRESS TempIp;

		if (ullLineNum >= (1 << 31)) goto err_too_large;

		sLineStart = ConsumeStringInSet(szHostsLine, NULL, PXCH_CONFIG_PARSE_WHITE);
		if (*sLineStart == L'#' || *sLineStart == L'\0') continue;

		sIpEnd = ConsumeStringInSet(sLineStart, NULL, PXCH_CONFIG_PARSE_IP_PORT);

		if (OptionGetIpPortValue((PXCH_IP_PORT*)&TempIp, NULL, sLineStart, sIpEnd, FALSE, TRUE)) goto err_invalid_hosts_with_msg;
		
		if (TempIp.CommonHeader.wPort != 0) {
			pszParseErrorMessage = L"IP with a port number not allowed here";
			goto err_invalid_hosts_with_msg;
		}

		sHostnameStart = ConsumeStringInSet(sIpEnd, NULL, PXCH_CONFIG_PARSE_WHITE);

		if (sHostnameStart == sIpEnd) {
			pszParseErrorMessage = L"No delimiter between IP and hostname";
			goto err_invalid_hosts_with_msg;
		}

		sHostnameEnd = ConsumeStringUntilSet(sHostnameStart, NULL, PXCH_CONFIG_PARSE_WHITE);
		if (sHostnameStart == sHostnameEnd) {
			pszParseErrorMessage = L"Empty hostname";
			goto err_invalid_hosts_with_msg;
		}

		while (1) {
			pHostsEntry = &PXCH_CONFIG_HOSTS_ENTRY_ARR(pPxchConfig)[dwHostsEntryCounter++];
			pHostsEntry->Hostname.wTag = PXCH_HOST_TYPE_HOSTNAME;
			StringCchCopyNW(pHostsEntry->Hostname.szValue, _countof(pHostsEntry->Hostname.szValue), sHostnameStart, sHostnameEnd - sHostnameStart);
			pHostsEntry->Ip = TempIp;
		
			sHostnameStart = ConsumeStringInSet(sHostnameEnd, NULL, PXCH_CONFIG_PARSE_WHITE);
			sHostnameEnd = ConsumeStringUntilSet(sHostnameStart, NULL, PXCH_CONFIG_PARSE_WHITE);
			if (sHostnameStart == sHostnameEnd) {
				break;
			}
		}
	}

	if (dwLastError != ERROR_END_OF_MEDIA) goto err_read_hosts;

	// Get winapi function addresses, calling helper if needed
	ZeroMemory(&pPxchConfig->FunctionPointers, sizeof(pPxchConfig->FunctionPointers));

	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, GetModuleHandleW   );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, LoadLibraryW       );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, GetProcAddress     );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, FreeLibrary        );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, GetLastError       );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, OutputDebugStringA );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, GetCurrentProcessId);
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, wsprintfA          );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, Sleep              );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, ExitThread         );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, ReleaseSemaphore   );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, CloseHandle        );
	ASSIGN_NATIVE_FUNC_ADDR(pPxchConfig, WaitForSingleObject);

#if (defined(_M_X64) || defined(__x86_64__)) && !defined(__CYGWIN__)
	{
		FILE* fHelperProcOut;
		fHelperProcOut = popen(szHelperX86CommandLine, "rt");

		if (fHelperProcOut == NULL) {
			LOGW(L"Warning: X86 Helper executable " WPRS L" not found. In this case proxychains.exe will not inject X86 descendant processes.", szHelperX86CommandLine);
		} else {
			unsigned long long tmp;
			int i;
			BOOL bStop = FALSE;

			for (i = 0; !bStop; i++) {
				if (fscanf(fHelperProcOut, "%llX", &tmp) != 1) {
#ifndef __CYGWIN__
					LOGW(L"Warning: Output from X86 Helper executable is in a wrong format. In this case proxychains.exe will not inject X86 descendant processes.");
#else
					LOGD(L"Warning: Output from X86 Helper executable is in a wrong format. In this case proxychains.exe will not inject X86 descendant processes.");
#endif
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, GetModuleHandleW   , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, LoadLibraryW       , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, GetProcAddress     , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, FreeLibrary        , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, GetLastError       , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, OutputDebugStringA , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, GetCurrentProcessId, NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, wsprintfA          , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, Sleep              , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, ExitThread         , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, ReleaseSemaphore   , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, CloseHandle        , NULL, X86);
					ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, WaitForSingleObject, NULL, X86);
					break;
				}
				switch (i) {
				case 0: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, GetModuleHandleW   , tmp, X86);
				break; case 1: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, LoadLibraryW       , tmp, X86);
				break; case 2: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, GetProcAddress     , tmp, X86);
				break; case 3: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, FreeLibrary        , tmp, X86);
				break; case 4: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, GetLastError       , tmp, X86);
				break; case 5: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, OutputDebugStringA , tmp, X86);
				break; case 6: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, GetCurrentProcessId, tmp, X86);
				break; case 7: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, wsprintfA          , tmp, X86);
				break; case 8: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, Sleep              , tmp, X86);
				break; case 9: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, ExitThread         , tmp, X86);
				break; case 10: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, ReleaseSemaphore  , tmp, X86);
				break; case 11: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, CloseHandle       , tmp, X86);
				break; case 12: ASSIGN_FUNC_ADDR_WITH_ARCH(pPxchConfig, WaitForSingleObject, tmp, X86);
				bStop = TRUE; break;
				default: bStop = TRUE; break;
				}
			}
		}
	}
#endif

	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, GetModuleHandleW   );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, LoadLibraryW       );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, GetProcAddress     );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, FreeLibrary        );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, GetLastError       );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, OutputDebugStringA );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, GetCurrentProcessId);
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, wsprintfA          );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, Sleep              );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, ExitThread         );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, ReleaseSemaphore   );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, CloseHandle        );
	PRINT_FUNC_ADDR_OF_BOTH_ARCH(pPxchConfig, WaitForSingleObject);

	return NO_ERROR;

err_general:
	return dwLastError;
err_insuf_buf:
	return ERROR_INSUFFICIENT_BUFFER;
err_dll_not_exist:
	LOGE(L"Error initializing DLL: DLL not found.");
	return ERROR_FILE_NOT_FOUND;
err_read_config:
	LOGE(L"Error reading configuration: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;
err_read_hosts:
	LOGE(L"Error reading hosts file: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;
err_invalid_config_with_msg:
	LOGE(L"Config line %llu: %ls", ullLineNum, pszParseErrorMessage);
	goto err_invalid_config;
err_invalid_hosts_with_msg:
	LOGE(L"Hosts file line %llu: %ls", ullLineNum, pszParseErrorMessage);
err_invalid_config:
	return ERROR_BAD_CONFIGURATION;
err_too_large:
	return ERROR_FILE_TOO_LARGE;
}


DWORD ParseArgs(PROXYCHAINS_CONFIG* pConfig, int argc, WCHAR* argv[], int* piCommandStart)
{
	int i;
	int iCountCommands = 0;
	BOOL bOptionFile = FALSE;
	BOOL bOptionLogLevel = FALSE;
	unsigned int iOptionPrefixLen;
	BOOL bOptionHasValue;
	BOOL bOptionsEnd = FALSE;
	BOOL bForceQuote = FALSE;
	DWORD dwLastError;
	WCHAR* pWchar;
	WCHAR* pCommandLine;

	pConfig->szConfigPath[0] = L'\0';
	pConfig->szCommandLine[0] = L'\0';
	pCommandLine = pConfig->szCommandLine;
	pConfig->dwLogLevel = PXCH_LOG_LEVEL_DEFAULT;
	pConfig->dwLogLevelSetByArg = FALSE;

	for (i = 1; i < argc; i++) {
		pWchar = argv[i];
		if (!bOptionsEnd) {

		option_value_following:
			if (bOptionFile) {
				if (FAILED(StringCchCopyW(pConfig->szConfigPath, _countof(pConfig->szConfigPath), pWchar))) goto err_insuf_buf;
				bOptionFile = FALSE;
				continue;
			}

			if (bOptionLogLevel) {
				WCHAR* pSavedWchar = pWchar;
				for (; *pSavedWchar; pSavedWchar++) *pSavedWchar = tolower(*pSavedWchar);
				if (wcscmp(pWchar, L"verbose") == 0 || wcscmp(pWchar, L"v") == 0) {
					pConfig->dwLogLevel = PXCH_LOG_LEVEL_VERBOSE;
				} else if (wcscmp(pWchar, L"debug") == 0 || wcscmp(pWchar, L"d") == 0) {
					pConfig->dwLogLevel = PXCH_LOG_LEVEL_DEBUG;
				} else if (wcscmp(pWchar, L"info") == 0 || wcscmp(pWchar, L"i") == 0) {
					pConfig->dwLogLevel = PXCH_LOG_LEVEL_INFO;
				} else if (wcscmp(pWchar, L"warning") == 0 || wcscmp(pWchar, L"w") == 0) {
					pConfig->dwLogLevel = PXCH_LOG_LEVEL_WARNING;
				} else if (wcscmp(pWchar, L"error") == 0 || wcscmp(pWchar, L"e") == 0) {
					pConfig->dwLogLevel = PXCH_LOG_LEVEL_ERROR;
				} else if (wcscmp(pWchar, L"critical") == 0 || wcscmp(pWchar, L"c") == 0) {
					pConfig->dwLogLevel = PXCH_LOG_LEVEL_CRITICAL;
				} else {
					goto err_log_level;
				}
				bOptionLogLevel = FALSE;
				pConfig->dwLogLevelSetByArg = TRUE;
				continue;
			}

			bOptionHasValue = FALSE;

			if (wcsncmp(pWchar, L"-f", 2) == 0) {
				bOptionFile = TRUE;
				iOptionPrefixLen = 2;
				bOptionHasValue = TRUE;
			}
			else if (wcsncmp(pWchar, L"-l", 2) == 0) {
				bOptionLogLevel = TRUE;
				iOptionPrefixLen = 2;
				bOptionHasValue = TRUE;
			}
			else if (wcsncmp(pWchar, L"-q", 2) == 0) {
				LOGD(L"Queit mode enabled in arguments");
				pConfig->dwLogLevel = PXCH_LOG_LEVEL_ERROR;
				pConfig->dwLogLevelSetByArg = TRUE;
				continue;
			}
			else if (wcsncmp(pWchar, L"-Q", 2) == 0 || wcsncmp(pWchar, L"-d", 2) == 0) {
				LOGD(L"Queit mode disabled in arguments");
				pConfig->dwLogLevelSetByArg = TRUE;
				continue;
			}
			else if (wcsncmp(pWchar, L"-h", 2) == 0 || wcsncmp(pWchar, L"--help", 4) == 0) {
				return ERROR_CANCELLED;
			}
			else if (wcsncmp(pWchar, L"--help", 2) == 0) {
				LOGD(L"Queit mode enabled in arguments");
				pConfig->dwLogLevel = PXCH_LOG_LEVEL_ERROR;
				pConfig->dwLogLevelSetByArg = TRUE;
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
#if defined(__CYGWIN__) && !defined(PXCH_MSYS_USE_WIN32_STYLE)
		*piCommandStart = i;
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
			WCHAR szExecPath[PXCH_MAX_COMMAND_EXEC_PATH_BUFSIZE];
			LPWSTR lpDummyFilePart;
			WCHAR szPathExtPath[PXCH_MAX_PATHEXT_BUFSIZE];
			WCHAR* pPathExtElemStart;
			WCHAR* pPathExt;

			if (GetEnvironmentVariableW(L"PATHEXT", szPathExtPath, _countof(szPathExtPath)) == _countof(szPathExtPath)) goto err_insuf_buf;

			if (TRUE || SearchPathW(NULL, pWchar, NULL, _countof(szExecPath), szExecPath, &lpDummyFilePart) == 0) {
				BOOL bSucceed = FALSE;
				
				pPathExt = szPathExtPath;
				pPathExtElemStart = szPathExtPath;
				while (1) {
					for (; *pPathExt && *pPathExt != L';'; pPathExt++)
						;

					if (*pPathExt == L'\0') break;
					*pPathExt = L'\0';
					
					if (SearchPathW(NULL, pWchar, pPathExtElemStart, _countof(szExecPath), szExecPath, &lpDummyFilePart)) {
						bSucceed = TRUE;
						break;
					}

					pPathExt++;
					pPathExtElemStart = pPathExt;
				}

				if (!bSucceed) goto err_get_exec_path;
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

err_log_level:
	LOGE(L"Error when parsing args: Unexpected log level");
	return ERROR_INVALID_PARAMETER;

err_insuf_buf:
	LOGE(L"Error when parsing args: Insufficient Buffer");
	return ERROR_INSUFFICIENT_BUFFER;

err_get_exec_path:
	dwLastError = GetLastError();
	LOGE(L"Error when parsing args: SearchPath() Failed. Command not found.");
	return dwLastError;

err_cmdline:
	dwLastError = GetLastError();
	LOGE(L"Error when parsing args: No command line provided");
	return ERROR_INVALID_COMMAND_LINE;
}
