// SPDX-License-Identifier: GPL-2.0-or-later
/* common.c
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
#include "common_win32.h"
#include "tls_generic.h"

wchar_t g_szDumpMemoryBuf_early[PXCH_MAX_DUMP_MEMORY_BUFSIZE];
wchar_t g_szErrorMessageBuf_early[PXCH_MAX_ERROR_MESSAGE_BUFSIZE];

wchar_t* g_szDumpMemoryBuf = g_szDumpMemoryBuf_early;
wchar_t* g_szErrorMessageBuf = g_szErrorMessageBuf_early;

static WCHAR szFwprintfWbuf[PXCH_MAX_FWPRINTF_BUFSIZE];
static CHAR szFwprintfBuf[PXCH_MAX_FWPRINTF_BUFSIZE];

const wchar_t* g_szRuleTargetDesc[3] = {
	L"DIRECT",
	L"PROXY",
	L"BLOCK",
};

void StdVwprintf(DWORD dwStdHandle, const WCHAR* fmt, va_list args)
{
	HANDLE h;
	STRSAFE_LPWSTR pEnd = szFwprintfWbuf;
	int iBufSize;
	DWORD cbWritten;

	szFwprintfWbuf[0] = L'\0';
	szFwprintfBuf[0] = '\0';

#ifdef __CYGWIN__
	pEnd = szFwprintfWbuf + newlib_vswprintf(szFwprintfWbuf, _countof(szFwprintfWbuf), fmt, args);
#else
	StringCchVPrintfExW(szFwprintfWbuf, _countof(szFwprintfWbuf), &pEnd, NULL, 0, fmt, args);
#endif

	if (pEnd < szFwprintfWbuf) pEnd = szFwprintfWbuf;

	if (szFwprintfWbuf[_countof(szFwprintfWbuf) - 2]) szFwprintfWbuf[_countof(szFwprintfWbuf) - 2] = L'\n';
	szFwprintfWbuf[_countof(szFwprintfWbuf) - 1] = L'\0';
	iBufSize = WideCharToMultiByte(CP_ACP, 0, szFwprintfWbuf, (int)(pEnd - szFwprintfWbuf), szFwprintfBuf, _countof(szFwprintfBuf), NULL, NULL);
	szFwprintfBuf[_countof(szFwprintfBuf) - 1] = '\0';

	h = GetStdHandle(dwStdHandle);
	if (h && h != INVALID_HANDLE_VALUE) WriteFile(h, szFwprintfBuf, iBufSize, &cbWritten, NULL);
}

void StdWprintf(DWORD dwStdHandle, const WCHAR* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
	StdVwprintf(dwStdHandle, fmt, args);
    va_end(args);
}

void StdFlush(DWORD dwStdHandle)
{
	HANDLE h;

	h = GetStdHandle(dwStdHandle);
	if (h) FlushFileBuffers(h);
}

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
		StringCchPrintfW(g_szErrorMessageBuf, PXCH_MAX_ERROR_MESSAGE_BUFSIZE, L"%ls(" WPRDW L")", buf, dwError);
		LocalFree(hLocalBuffer);
	}
	else {
		StringCchPrintfW(g_szErrorMessageBuf, PXCH_MAX_ERROR_MESSAGE_BUFSIZE, L"(" WPRDW L")", dwError);
	}
	return g_szErrorMessageBuf;
}

const wchar_t* DumpMemory(const void* p, int iLength)
{
	int i;
	wchar_t* pDumpMemoryBuf = g_szDumpMemoryBuf;

	if (iLength == 0) iLength = 64;
	for (i = 0; i < iLength; i++) {
		StringCchPrintfExW(pDumpMemoryBuf, PXCH_MAX_DUMP_MEMORY_BUFSIZE - (pDumpMemoryBuf - g_szDumpMemoryBuf), &pDumpMemoryBuf, NULL, 0, L"%02x ", (unsigned int)*((const unsigned char*)p + i));
	}
	return g_szDumpMemoryBuf;
}
