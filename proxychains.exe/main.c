#include <sdkddkver.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include <locale.h>
#include <Shlwapi.h>

#include "proxychains_struct.h"

#pragma comment(lib, "Shlwapi.lib")

DWORD LoadConfiguration(PROXYCHAINS_CONFIG* pPxchConfig)
{
	DWORD dwRet;
	size_t dirLength = 0;

	pPxchConfig->testNum = 1234;

	dwRet = GetModuleFileName(NULL, pPxchConfig->szDllPath, MAX_DLL_PATH_BUFSIZE);
	if (dwRet == 0) goto err_insuf_buf;
	if (dwRet == MAX_DLL_PATH_BUFSIZE) goto err_insuf_buf;

	if (!PathRemoveFileSpec(pPxchConfig->szDllPath)) goto err_insuf_buf;

	if (FAILED(StringCchCat(pPxchConfig->szDllPath, MAX_DLL_PATH_BUFSIZE, _T("\\")))) goto err_insuf_buf;
	if (FAILED(StringCchCat(pPxchConfig->szDllPath, MAX_DLL_PATH_BUFSIZE, szDllFileName))) goto err_insuf_buf;
	
	return 0;

//err_other:
//	return GetLastError();
err_insuf_buf:
	return ERROR_INSUFFICIENT_BUFFER;
}

void MyPrintError(DWORD dwError)
{
	BOOL formatOk;
	HLOCAL hLocalBuffer;
	HMODULE hDll;
	

	DWORD neutralLocale = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
	formatOk = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, neutralLocale, (PTSTR)&hLocalBuffer, 0, NULL);
	if (formatOk) goto after_fmt;

	hDll = LoadLibraryEx(_T("netmsg.dll"), NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (hDll != NULL) {
		formatOk = FormatMessage(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, hDll, dwError, neutralLocale, (PTSTR)&hLocalBuffer, 0, NULL);
		FreeLibrary(hDll);
	}

after_fmt:
	if (formatOk && hLocalBuffer != NULL) {
		PCTSTR buf = (PCTSTR)LocalLock(hLocalBuffer);
		_ftprintf(stderr, _T("Error %ld: %s\n"), dwError, buf);
		LocalFree(hLocalBuffer);
	}
	else {
		_ftprintf(stderr, _T("Error %ld: Unknown Error.\n"), dwError);
	}
}

BOOL ArgHasSpecialChar(_TCHAR* sz)
{
	_TCHAR* p = sz;
	while (*p) {
		if (*p == _T('\t')) return TRUE;
		if (*p == _T('\n')) return TRUE;
		if (*p == _T('\v')) return TRUE;
		if (*p == _T('\"')) return TRUE;
		p++;
	}
	return FALSE;
}

DWORD ParseArgs(PROXYCHAINS_CONFIG* pConfig, int argc, _TCHAR* argv[])
{
	int i;
	int iCountCommands = 0;
	BOOL bOptionFile = FALSE;
	int iOptionPrefixLen;
	BOOL bOptionHasValue;
	BOOL bOptionsEnd = FALSE;
	BOOL bForceQuote = FALSE;
	DWORD dwErrorCode;
	_TCHAR* pTchar;
	_TCHAR* pCommandLine;

	pConfig->szConfigPath[0] = _T('\0');
	pConfig->szCommandLine[0] = _T('\0');
	pCommandLine = pConfig->szCommandLine;

	for (i = 1; i < argc; i++) {
		pTchar = argv[i];
		if (!bOptionsEnd) {

		option_value_following:
			if (bOptionFile) {
				if (FAILED(StringCchCopy(pConfig->szConfigPath, _countof(pConfig->szConfigPath), pTchar))) goto err_insuf_buf;
				bOptionFile = FALSE;
				continue;
			}

			bOptionHasValue = FALSE;

			if (_tcsncmp(pTchar, _T("-f"), 2) == 0) {
				bOptionFile = TRUE;
				iOptionPrefixLen = 2;
				bOptionHasValue = TRUE;
			} else if (_tcscmp(pTchar, _T("-q")) == 0) {
				pPxchConfig->quiet = TRUE;
				continue;
			} else {
				bOptionsEnd = TRUE;
				i--;
				continue;
			}

			if (bOptionHasValue) {
				if (_tcslen(pTchar) > iOptionPrefixLen) {
					pTchar += 2;
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
			*(pCommandLine++) = _T(' ');
		}
		else {
			_TCHAR szExecPath[MAX_COMMAND_EXEC_PATH_BUFSIZE];
			if (SearchPath(NULL, pTchar, NULL, _countof(szExecPath), szExecPath, NULL) == 0) {
				if (SearchPath(NULL, pTchar, _T(".exe"), _countof(szExecPath), szExecPath, NULL) == 0) {
					goto err_get_exec_path;
				}
			}
			pTchar = szExecPath;
		}

		if (!bForceQuote && pTchar != _T('\0') && !ArgHasSpecialChar(pTchar)) {
			if (FAILED(StringCchCopyEx(pCommandLine, _countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine), pTchar, &pCommandLine, NULL, 0))) goto err_insuf_buf;
		}
		else {
			if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
				goto err_insuf_buf;
			}
			*(pCommandLine++) = _T('"');

			while (*pTchar) {
				UINT32 uCountBackslashes = 0;
				while (*pTchar && *pTchar == _T('\\')) {
					pTchar++;
					uCountBackslashes++;
				}
				if (*pTchar == _T('\0')) {
					UINT32 u;
					uCountBackslashes *= 2;
					for (u = 0; u < uCountBackslashes; u++) {
						if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
							goto err_insuf_buf;
						}
						*(pCommandLine++) = _T('\\');
					}
				}
				else if (*pTchar == _T('"')) {
					UINT32 u;
					uCountBackslashes *= 2;
					uCountBackslashes += 1;
					for (u = 0; u < uCountBackslashes + 1; u++) {
						if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
							goto err_insuf_buf;
						}
						if (u != uCountBackslashes) {
							*(pCommandLine++) = _T('\\');
						}
						else {
							*(pCommandLine++) = _T('"');
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
							*(pCommandLine++) = _T('\\');
						}
						else {
							*(pCommandLine++) = *pTchar;
						}
					}
				}

				if (*pTchar == _T('\0')) {
					break;
				}
				pTchar++;
			}
			if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
				goto err_insuf_buf;
			}
			*(pCommandLine++) = _T('"');
		}
	}
	*pCommandLine = _T('\0');
	return 0;

err_insuf_buf:
	_ftprintf(stderr, _T("Error when parsing args: Insufficient Buffer\n"));
	return ERROR_INSUFFICIENT_BUFFER;

err_get_exec_path:
	dwErrorCode = GetLastError();
	_ftprintf(stderr, _T("Error when parsing args: SearchPath() Failed %lu\n"), dwErrorCode);
	return dwErrorCode;
}

int _tmain(int argc, _TCHAR* argv[])
{
	PROXYCHAINS_CONFIG config = { 0 };
	DWORD dwError;
	STARTUPINFO startupInfo = { 0 };
	PROCESS_INFORMATION processInformation = { 0 };

	setlocale(LC_ALL, "");

	if ((dwError = LoadConfiguration(&config)) != NOERROR) goto err;
	
	_tprintf(_T("DLL Path: %s\n"), config.szDllPath);

	pPxchConfig = &config;
	
	InitHook(NULL);

	if ((dwError = ParseArgs(pPxchConfig, argc, argv)) != NOERROR) goto err;

	_tprintf(_T("Config Path: %s\n"), config.szConfigPath);
	_tprintf(_T("Quiet: %s\n"), config.quiet ? _T("Y") : _T("N"));
	_tprintf(_T("Command Line: %s\n"), config.szCommandLine);

	CreateProcess(NULL, config.szCommandLine, 0, 0, 1, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, 0, 0, &startupInfo, &processInformation);

	ResumeThread(processInformation.hThread);
	WaitForSingleObject(processInformation.hProcess, INFINITE);
	
	return 0;

err:
	MyPrintError(dwError);
	return dwError;
}