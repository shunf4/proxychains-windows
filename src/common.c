#include "stdafx.h"
#include <strsafe.h>
#include "common.h"

WCHAR szErrorMessage[MAX_ERROR_MESSAGE_BUFSIZE];

PWCHAR FormatErrorToStr(DWORD dwError)
{
	DWORD dwCb;
	HLOCAL hLocalBuffer;
	HMODULE hDll;

	DWORD neutralLocale = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
	dwCb = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, neutralLocale, (LPWSTR)&hLocalBuffer, 0, NULL);
	if (dwCb) goto after_fmt;

	// Might be a network error
	hDll = LoadLibraryExW(L"netmsg.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (hDll != NULL) {
		dwCb = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, hDll, dwError, neutralLocale, (LPWSTR)&hLocalBuffer, 0, NULL);
		FreeLibrary(hDll);
	}

after_fmt:
	if (dwCb && hLocalBuffer != NULL) {
		PWSTR buf = (PWSTR)LocalLock(hLocalBuffer);
		if (buf[dwCb - 1] == L'\n') {
			buf[dwCb - 1] = L'\0';
		}
		if (buf[dwCb - 2] == L'\r') {
			buf[dwCb - 2] = L'\0';
		}
		StringCchPrintfW(szErrorMessage, MAX_ERROR_MESSAGE_BUFSIZE, L"%ls(%lu)", buf, dwError);
		LocalFree(hLocalBuffer);
	}
	else {
		StringCchPrintfW(szErrorMessage, MAX_ERROR_MESSAGE_BUFSIZE, L"(%lu)", dwError);
	}
	return szErrorMessage;
}

void PrintErrorToFile(FILE* f, DWORD dwError)
{
	FormatErrorToStr(dwError);
	fwprintf(f, L"Error: %ls\n", szErrorMessage);
}
