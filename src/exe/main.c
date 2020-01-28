#include "stdafx.h"
#include <Shlwapi.h>
#ifdef __CYGWIN__
#include <strsafe.h>
#endif
#include <locale.h>
#include <ShellAPI.h>

#include "pxch_defines.h"
#include "pxch_hook.h"
#include "common.h"
#include "log.h"

#ifndef __CYGWIN__
#pragma comment(lib, "Shlwapi.lib")
#endif

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
		wprintf(L"Ctrl-C event");
		Beep(750, 300);
		return TRUE;

		// CTRL-CLOSE: confirm that the user wants to exit. 
	case CTRL_CLOSE_EVENT:
		Beep(600, 200);
		wprintf(L"Ctrl-Close event");
		return TRUE;

		// Pass other signals to the next handler. 
	case CTRL_BREAK_EVENT:
		Beep(900, 200);
		wprintf(L"Ctrl-Break event");
		return FALSE;

	case CTRL_LOGOFF_EVENT:
		Beep(1000, 200);
		wprintf(L"Ctrl-Logoff event");
		return FALSE;

	case CTRL_SHUTDOWN_EVENT:
		Beep(750, 500);
		wprintf(L"Ctrl-Shutdown event");
		return FALSE;

	default:
		return FALSE;
	}
}

DWORD LoadConfiguration(PROXYCHAINS_CONFIG* pPxchConfig)
{
	DWORD dwRet;
	//SIZE_T dirLength = 0;

	pPxchConfig->testNum = 1234;

	dwRet = GetModuleFileNameW(NULL, pPxchConfig->szDllPath, MAX_DLL_PATH_BUFSIZE);
	if (dwRet == 0) goto err_insuf_buf;
	if (dwRet == MAX_DLL_PATH_BUFSIZE) goto err_insuf_buf;

	if (!PathRemoveFileSpecW(pPxchConfig->szDllPath)) goto err_insuf_buf;

	if (FAILED(StringCchCatW(pPxchConfig->szDllPath, MAX_DLL_PATH_BUFSIZE, L"\\"))) goto err_insuf_buf;
	if (FAILED(StringCchCatW(pPxchConfig->szDllPath, MAX_DLL_PATH_BUFSIZE, szDllFileName))) goto err_insuf_buf;
	
	return 0;

//err_other:
//	return GetLastError();
err_insuf_buf:
	return ERROR_INSUFFICIENT_BUFFER;
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

DWORD ParseArgs(PROXYCHAINS_CONFIG* pConfig, int argc, WCHAR* argv[])
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
			} else if (wcsncmp(pWchar, L"-q", 2) == 0) {
				pPxchConfig->quiet = TRUE;
				continue;
			} else {
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

		// Option Ends, Command starts
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
	return 0;

err_insuf_buf:
	LOGE(L"Error when parsing args: Insufficient Buffer");
	return ERROR_INSUFFICIENT_BUFFER;

err_get_exec_path:
	dwErrorCode = GetLastError();
	LOGE(L"Error when parsing args: SearchPath() Failed: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;
}


int wmain(int argc, WCHAR* argv[])
{
	PROXYCHAINS_CONFIG config = { 0 };
	DWORD dwError;
	STARTUPINFO startupInfo = { 0 };
	PROCESS_INFORMATION processInformation = { 0 };

#ifdef __CYGWIN__
	LOGI(L"Locale: %s\n", setlocale(LC_ALL, "zh_CN.UTF-8"));
#else
	LOGI(L"Locale: %S\n", setlocale(LC_ALL, "zh_CN.UTF-8"));
#endif
	SetConsoleCtrlHandler(CtrlHandler, TRUE);

	if ((dwError = LoadConfiguration(&config)) != NOERROR) goto err;
	
	LOGI(L"DLL Path: %ls", config.szDllPath);

	pPxchConfig = &config;
	
	InitHookForMain();

	if ((dwError = ParseArgs(pPxchConfig, argc, argv)) != NOERROR) goto err;

	LOGI(L"Config Path: %ls", config.szConfigPath);
	LOGI(L"Quiet: %ls", config.quiet ? L"Y" : L"N");
	LOGI(L"Command Line: %ls", config.szCommandLine);

	ProxyCreateProcessW(NULL, config.szCommandLine, 0, 0, 1, 0, 0, 0, &startupInfo, &processInformation);
	//CreateProcessW(NULL, config.szCommandLine, 0, 0, 1, 0, 0, 0, &startupInfo, &processInformation);

	WaitForSingleObject(processInformation.hProcess, INFINITE);
	
	return 0;

err:
	PrintErrorToFile(stderr, dwError);
	return dwError;
}

#ifdef __CYGWIN__
int main(int argc, char* argv[])
{
	int i;
	WCHAR** wargv = malloc(argc * sizeof(WCHAR*));
	for (i = 0; i < argc; i++) {
		int iNeededChars = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
		wargv[i] = malloc(iNeededChars * sizeof(WCHAR));
		MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wargv[i], iNeededChars);
	}

	return wmain(argc, wargv);
}
#endif