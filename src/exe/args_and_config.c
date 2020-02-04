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

DWORD LoadConfiguration(PROXYCHAINS_CONFIG** ppPxchConfig)
{
	WSADATA wsaData;
	DWORD dwRet;
	FILETIME ft;
	ULARGE_INTEGER uli;
	PROXYCHAINS_CONFIG* pPxchConfig;
	int iRuleNum;
	int iProxyNum;
	//SIZE_T dirLength = 0;

	WSAStartup(MAKEWORD(2, 2), &wsaData);

	iRuleNum = 2;
	iProxyNum = 1;
	pPxchConfig = *ppPxchConfig = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PROXYCHAINS_CONFIG) + PXCHCONFIG_EXTRA_SIZE_BY_N(iProxyNum, iRuleNum));

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

	pPxchConfig->dwProxyNum = iProxyNum;
	pPxchConfig->cbProxyListOffset = sizeof(PROXYCHAINS_CONFIG);
	pPxchConfig->dwRuleNum = iRuleNum;
	pPxchConfig->cbRuleListOffset = sizeof(PROXYCHAINS_CONFIG) + (sizeof(PXCH_PROXY_DATA) * pPxchConfig->dwProxyNum);

	{
		PXCH_PROXY_DATA* proxy = &PXCHCONFIG_PROXY_ARR(pPxchConfig)[0];
		ProxyInit(*proxy);
		SetProxyType(SOCKS5, *proxy);
		SetHostType(IPV4, proxy->Socks5.HostPort);
		proxy->Socks5.iSockLen = sizeof(proxy->Socks5.HostPort);
		WSAStringToAddressW(L"127.0.0.1:1079", AF_INET, NULL, (LPSOCKADDR)&proxy->Socks5.HostPort, &proxy->Socks5.iSockLen);
		proxy->Socks5.szUsername[0] = '\0';
		proxy->Socks5.szPassword[0] = '\0';
		proxy->Socks5.Ws2_32FpConnect = &Ws2_32Socks5Connect;
		proxy->Socks5.Ws2_32FpHandshake = &Ws2_32Socks5Handshake;
	}

	{
		PXCH_RULE* rule = &PXCHCONFIG_RULE_ARR(pPxchConfig)[0];
		int iSockLen = sizeof(PXCH_IP_ADDRESS);
		RuleInit(*rule);
		SetRuleType(IP_CIDR, *rule);

		ZeroMemory(&rule->HostAddress, sizeof(rule->HostAddress));
		SetHostType(IPV4, rule->HostAddress);
		WSAStringToAddressW(L"127.0.0.1", AF_INET, NULL, (LPSOCKADDR)&rule->HostAddress.IpPort, &iSockLen);
		rule->dwCidrPrefixLength = 32;
		rule->iWillProxy = FALSE;
	}

	{
		PXCH_RULE* rule = &PXCHCONFIG_RULE_ARR(pPxchConfig)[1];
		int iSockLen = sizeof(PXCH_IP_ADDRESS);
		RuleInit(*rule);
		SetRuleType(IP_CIDR, *rule);

		ZeroMemory(&rule->HostAddress, sizeof(rule->HostAddress));
		SetHostType(IPV4, rule->HostAddress);
		WSAStringToAddressW(L"0.0.0.0", AF_INET, NULL, (LPSOCKADDR)&rule->HostAddress.IpPort, &iSockLen);
		rule->dwCidrPrefixLength = 0;
		rule->iWillProxy = TRUE;
	}

	return 0;

	//err_other:
	//	return GetLastError();
err_insuf_buf:
	return ERROR_INSUFFICIENT_BUFFER;

err_dll_not_exist:
	return ERROR_FILE_NOT_FOUND;
}


BOOL ArgHasSpecialChar(WCHAR* sz)
{
	WCHAR* p = sz;
	while (*p) {
		if (*p == L'\t') return TRUE;
		if (*p == L'\n') return TRUE;
		if (*p == L'\v') return TRUE;
		if (*p == L'\"') return TRUE;
		p++;
	}
	return FALSE;
}


DWORD ParseArgs(PROXYCHAINS_CONFIG* pConfig, int argc, WCHAR* argv[], int* piCommandStart)
{
	int i;
	int iCountCommands = 0;
	BOOL bOptionFile = FALSE;
	int iOptionPrefixLen;
	BOOL bOptionHasValue;
	BOOL bOptionsEnd = FALSE;
	BOOL bForceQuote = FALSE;
	DWORD dwErrorCode;
	WCHAR* pWchar;
	WCHAR* pCommandLine;

	pConfig->szConfigPath[0] = L'\0';
	pConfig->szCommandLine[0] = L'\0';
	pCommandLine = pConfig->szCommandLine;

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
				pConfig->iIsQuiet = TRUE;
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
		iCountCommands++;
		if (iCountCommands > 1) {
			if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
				goto err_insuf_buf;
			}
			*(pCommandLine++) = L' ';
		}
		else {
			WCHAR szExecPath[MAX_COMMAND_EXEC_PATH_BUFSIZE];
			if (SearchPath(NULL, pWchar, NULL, _countof(szExecPath), szExecPath, NULL) == 0) {
				if (SearchPath(NULL, pWchar, L".exe", _countof(szExecPath), szExecPath, NULL) == 0) {
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

	if (iCountCommands == 0) {
		return ERROR_INVALID_COMMAND_LINE;
	}

	return 0;

err_insuf_buf:
	LOGE(L"Error when parsing args: Insufficient Buffer");
	return ERROR_INSUFFICIENT_BUFFER;

err_get_exec_path:
	dwErrorCode = GetLastError();
	LOGE(L"Error when parsing args: SearchPath() Failed: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;
}
