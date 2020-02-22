// SPDX-License-Identifier: GPL-2.0-or-later
/* dllutil_log_func.c
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

const PXCH_UINT32 g_dwW32SystemTimeSize = sizeof(SYSTEMTIME);

WCHAR log_ods_buf_early[PXCH_LOG_ODS_BUFSIZE];

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

const wchar_t* DumpMemory(const void* p, int iLength)
{
	int i;
	wchar_t* szDumpMemoryBuf = PXCH_TLS_PTR_DUMP_MEMORY_BUF(g_dwTlsIndex);
	wchar_t* pDumpMemoryBuf = szDumpMemoryBuf;

	if (iLength == 0) iLength = 64;
	for (i = 0; i < iLength; i++) {
		StringCchPrintfExW(pDumpMemoryBuf, PXCH_MAX_DUMP_MEMORY_BUFSIZE - (pDumpMemoryBuf - szDumpMemoryBuf), &pDumpMemoryBuf, NULL, 0, L"%02x ", (unsigned int)*((const unsigned char*)p + i));
	}
	return szDumpMemoryBuf;
}