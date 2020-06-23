// SPDX-License-Identifier: GPL-2.0-or-later
/* hookdll_util_log_win32.c
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
#include "log_win32.h"
#include "tls_generic.h"
#include "hookdll_generic.h"
#include "hookdll_util_win32.h"

HANDLE g_hCygwinConsoleSemaphore;

PXCH_DLL_API PXCH_UINT32 g_dwTlsIndex = TLS_OUT_OF_INDEXES;
PXCH_DLL_API const PXCH_UINT32 g_dwW32SystemTimeSize = sizeof(SYSTEMTIME);

PXCH_DLL_API SYSTEMTIME log_time_early;
PXCH_DLL_API wchar_t log_szLogLine_early[PXCH_MAX_FWPRINTF_BUFSIZE] = { 0 };
PXCH_DLL_API SYSTEMTIME log_time_early;
PXCH_DLL_API PXCH_IPC_MSGBUF log_msg_early;
PXCH_DLL_API PXCH_IPC_MSGBUF log_respMsg_early;
PXCH_DLL_API PXCH_UINT32 log_cbMsgSize_early;
PXCH_DLL_API PXCH_UINT32 log_cbRespMsgSize_early;
PXCH_DLL_API PXCH_UINT32 log_pid_early;
PXCH_DLL_API PXCH_UINT32 log_tid_early;
PXCH_DLL_API wchar_t log_ods_buf_early[PXCH_LOG_ODS_BUFSIZE];
#ifdef __CYGWIN__
PXCH_DLL_API PXCH_UINT32 log_cygpid_early;
#endif
PXCH_DLL_API WCHAR log_ods_buf_early[PXCH_LOG_ODS_BUFSIZE];

PXCH_DLL_API wchar_t g_szDumpMemoryBuf_early[PXCH_MAX_DUMP_MEMORY_BUFSIZE];
PXCH_DLL_API wchar_t g_szErrorMessageBuf_early[PXCH_MAX_ERROR_MESSAGE_BUFSIZE];

PXCH_DLL_API wchar_t g_szFwprintfWbuf_early[PXCH_MAX_FWPRINTF_BUFSIZE];
PXCH_DLL_API char g_szFwprintfBuf_early[PXCH_MAX_FWPRINTF_BUFSIZE];

const wchar_t* g_szRuleTargetDesc[3] = {
	L"DIRECT",
	L"PROXY",
	L"BLOCK",
};


void pxchlog_ipc_func_e(const wchar_t* prefix_fmt, const wchar_t* ipc_prefix_fmt, const wchar_t* fmt, ...)
{
	va_list args;

	PXCH_LOG_IPC_PID_QUERY();
	if (g_pPxchConfig && log_pid == g_pPxchConfig->dwMasterProcessId) {
		GetLocalTime(&log_time);
		StdWprintf(STD_ERROR_HANDLE, prefix_fmt, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond);
		va_start(args, fmt);
		StdVwprintf(STD_ERROR_HANDLE, fmt, args);
		va_end(args);
		StdFlush(STD_ERROR_HANDLE);
	} else {
		wchar_t* p = log_szLogLine;

		GetLocalTime(&log_time);
		log_szLogLine[0] = L'\0';
		StringCchPrintfExW(log_szLogLine, PXCH_MAX_FWPRINTF_BUFSIZE, &p, NULL, 0, ipc_prefix_fmt, PXCH_LOG_IPC_PID_VALUE, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond);

		va_start(args, fmt);
		StringCchVPrintfExW(p, PXCH_MAX_FWPRINTF_BUFSIZE - (p - log_szLogLine), NULL, NULL, 0, fmt, args);
		va_end(args);

		if (log_szLogLine[PXCH_MAX_FWPRINTF_BUFSIZE - 2]) log_szLogLine[PXCH_MAX_FWPRINTF_BUFSIZE - 2] = L'\n';
		log_szLogLine[PXCH_MAX_FWPRINTF_BUFSIZE - 1] = L'\0';

		WstrToMessage(log_msg, &log_cbMsgSize, log_szLogLine);
		IpcCommunicateWithServer(log_msg, log_cbMsgSize, log_respMsg, &log_cbRespMsgSize);
	}
}

void pxchlog_ipc_func(const wchar_t* prefix_fmt, const wchar_t* ipc_prefix_fmt, const wchar_t* fmt, ...)
{
	va_list args;

	PXCH_LOG_IPC_PID_QUERY();
	if (g_pPxchConfig && log_pid == g_pPxchConfig->dwMasterProcessId) {
		GetLocalTime(&log_time);
		StdWprintf(STD_OUTPUT_HANDLE, prefix_fmt, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond);
		va_start(args, fmt);
		StdVwprintf(STD_OUTPUT_HANDLE, fmt, args);
		va_end(args);
		StdFlush(STD_OUTPUT_HANDLE);
	} else {
		wchar_t* p = log_szLogLine;

		GetLocalTime(&log_time);
		log_szLogLine[0] = L'\0';
		StringCchPrintfExW(log_szLogLine, PXCH_MAX_FWPRINTF_BUFSIZE, &p, NULL, 0, ipc_prefix_fmt, PXCH_LOG_IPC_PID_VALUE, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond);

		va_start(args, fmt);
		StringCchVPrintfExW(p, PXCH_MAX_FWPRINTF_BUFSIZE - (p - log_szLogLine), NULL, NULL, 0, fmt, args);
		va_end(args);

		if (log_szLogLine[PXCH_MAX_FWPRINTF_BUFSIZE - 2]) log_szLogLine[PXCH_MAX_FWPRINTF_BUFSIZE - 2] = L'\n';
		log_szLogLine[PXCH_MAX_FWPRINTF_BUFSIZE - 1] = L'\0';

		WstrToMessage(log_msg, &log_cbMsgSize, log_szLogLine);
		IpcCommunicateWithServer(log_msg, log_cbMsgSize, log_respMsg, &log_cbRespMsgSize);
	}
}


PXCH_DLL_API void StdVwprintf(DWORD dwStdHandle, const WCHAR* fmt, va_list args)
{
	STRSAFE_LPWSTR pEnd = g_szFwprintfWbuf;
	int iBufSize;
#ifndef __CYGWIN__
	HANDLE h;
	DWORD cbWritten;
#endif // __CYGWIN__

	g_szFwprintfWbuf[0] = L'\0';
	g_szFwprintfBuf[0] = '\0';

#ifdef __CYGWIN__
	pEnd = g_szFwprintfWbuf + newlib_vswprintf(g_szFwprintfWbuf, PXCH_MAX_FWPRINTF_BUFSIZE, fmt, args);
#else
	StringCchVPrintfExW(g_szFwprintfWbuf, PXCH_MAX_FWPRINTF_BUFSIZE, &pEnd, NULL, 0, fmt, args);
#endif

	if (pEnd < g_szFwprintfWbuf) pEnd = g_szFwprintfWbuf;

	if (g_szFwprintfWbuf[PXCH_MAX_FWPRINTF_BUFSIZE - 2]) g_szFwprintfWbuf[PXCH_MAX_FWPRINTF_BUFSIZE - 2] = L'\n';
	g_szFwprintfWbuf[PXCH_MAX_FWPRINTF_BUFSIZE - 1] = L'\0';
	iBufSize = WideCharToMultiByte(
#ifndef __CYGWIN__
		CP_ACP
#else // __CYGWIN__
		CP_UTF8
#endif // __CYGWIN__
	, 0, g_szFwprintfWbuf, (int)(pEnd - g_szFwprintfWbuf), g_szFwprintfBuf, PXCH_MAX_FWPRINTF_BUFSIZE, NULL, NULL);
	g_szFwprintfBuf[PXCH_MAX_FWPRINTF_BUFSIZE - 1] = '\0';

#ifndef __CYGWIN__
	h = GetStdHandle(dwStdHandle);
	if (h && h != INVALID_HANDLE_VALUE) WriteFile(h, g_szFwprintfBuf, iBufSize, &cbWritten, NULL);
#else // __CYGWIN__
	DWORD dwWaitResult;
	DWORD dwLastError;

	ODBGSTRLOGV(L"Waiting for g_hCygwinConsoleSemaphore.");

	dwWaitResult = WaitForSingleObject(g_hCygwinConsoleSemaphore, 0);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		if (dwStdHandle == STD_OUTPUT_HANDLE) {
			pxch_cygwin_write(1, g_szFwprintfBuf, (size_t)iBufSize);
		} else if (dwStdHandle == STD_ERROR_HANDLE) {
			pxch_cygwin_write(2, g_szFwprintfBuf, (size_t)iBufSize);
		}
		if (!ReleaseSemaphore(g_hCygwinConsoleSemaphore, 1, NULL)) {
			dwLastError = GetLastError();
			ODBGSTRLOGD(L"Release g_hCygwinConsoleSemaphore error: %ls", FormatErrorToStr(dwLastError));
			exit(dwLastError);
		}
		break;

	case WAIT_ABANDONED:
		ODBGSTRLOGD(L"g_hCygwinConsoleSemaphore abandoned!");
		Sleep(INFINITE);
		exit(ERROR_ABANDONED_WAIT_0);
		break;

	case WAIT_TIMEOUT:
		ODBGSTRLOGD(L"g_hCygwinConsoleSemaphore is currently unavailable, not outputing: %ls", g_szFwprintfWbuf);
		break;

	default:
		dwLastError = GetLastError();
		ODBGSTRLOGD(L"Wait for g_hCygwinConsoleSemaphore(%p) status: " WPRDW L"; error: %ls", g_hCygwinConsoleSemaphore, dwWaitResult, FormatErrorToStr(dwLastError));
		exit(dwLastError);
	}
#endif // __CYGWIN__
}


PXCH_DLL_API void StdWprintf(DWORD dwStdHandle, const WCHAR* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	StdVwprintf(dwStdHandle, fmt, args);
	va_end(args);
}


PXCH_DLL_API void StdFlush(DWORD dwStdHandle)
{
	HANDLE h;

	h = GetStdHandle(dwStdHandle);
	if (h && h != INVALID_HANDLE_VALUE) FlushFileBuffers(h);
}


PXCH_DLL_API PWCHAR FormatErrorToStr(DWORD dwError)
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

PXCH_DLL_API const wchar_t* DumpMemory(const void* p, int iLength)
{
	int i;
	wchar_t* pDumpMemoryBuf = g_szDumpMemoryBuf;

	if (iLength == 0) iLength = 64;
	for (i = 0; i < iLength; i++) {
		StringCchPrintfExW(pDumpMemoryBuf, PXCH_MAX_DUMP_MEMORY_BUFSIZE - (pDumpMemoryBuf - g_szDumpMemoryBuf), &pDumpMemoryBuf, NULL, 0, L"%02x ", (unsigned int)*((const unsigned char*)p + i));
	}
	return g_szDumpMemoryBuf;
}
