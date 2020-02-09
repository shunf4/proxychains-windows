#include "log_win32.h"

void pxchlog_ipc_func_e(const wchar_t* prefix_fmt, const wchar_t* ipc_prefix_fmt, const wchar_t* fmt, ...)
{
    va_list args;

    PXCHLOG_IPC_PID_QUERY();
    if (g_pPxchConfig && log_pid == g_pPxchConfig->dwMasterProcessId) {
        GetLocalTime(&log_time);
        StdWprintf(STD_ERROR_HANDLE, prefix_fmt, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond);
        va_start(args, fmt);
        StdVwprintf(STD_ERROR_HANDLE, fmt, args);
        va_end(args);
		StdFlush(STD_ERROR_HANDLE);
    } else {
        WCHAR* p = log_szLogLine;

        GetLocalTime(&log_time);
        log_szLogLine[0] = L'\0';
        StringCchPrintfExW(log_szLogLine, _countof(log_szLogLine), &p, NULL, 0, ipc_prefix_fmt, PXCHLOG_IPC_PID_VALUE, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond);

        va_start(args, fmt);
        StringCchVPrintfExW(p, _countof(log_szLogLine) - (p - log_szLogLine), NULL, NULL, 0, fmt, args);
        va_end(args);

        if (log_szLogLine[_countof(log_szLogLine) - 2]) log_szLogLine[_countof(log_szLogLine) - 2] = L'\n';
        log_szLogLine[_countof(log_szLogLine) - 1] = L'\0';

        WstrToMessage(log_msg, &log_cbMsgSize, log_szLogLine);
        IpcCommunicateWithServer(log_msg, log_cbMsgSize, log_respMsg, &log_cbRespMsgSize);
	}
}

void pxchlog_ipc_func(const wchar_t* prefix_fmt, const wchar_t* ipc_prefix_fmt, const wchar_t* fmt, ...)
{
    va_list args;

    PXCHLOG_IPC_PID_QUERY();
    if (g_pPxchConfig && log_pid == g_pPxchConfig->dwMasterProcessId) {
        GetLocalTime(&log_time);
        StdWprintf(STD_OUTPUT_HANDLE, prefix_fmt, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond);
        va_start(args, fmt);
        StdVwprintf(STD_OUTPUT_HANDLE, fmt, args);
        va_end(args);
		StdFlush(STD_OUTPUT_HANDLE);
    } else {
        WCHAR* p = log_szLogLine;

        GetLocalTime(&log_time);
        log_szLogLine[0] = L'\0';
        StringCchPrintfExW(log_szLogLine, _countof(log_szLogLine), &p, NULL, 0, ipc_prefix_fmt, PXCHLOG_IPC_PID_VALUE, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond);

        va_start(args, fmt);
        StringCchVPrintfExW(p, _countof(log_szLogLine) - (p - log_szLogLine), NULL, NULL, 0, fmt, args);
        va_end(args);

        if (log_szLogLine[_countof(log_szLogLine) - 2]) log_szLogLine[_countof(log_szLogLine) - 2] = L'\n';
        log_szLogLine[_countof(log_szLogLine) - 1] = L'\0';

        WstrToMessage(log_msg, &log_cbMsgSize, log_szLogLine);
        IpcCommunicateWithServer(log_msg, log_cbMsgSize, log_respMsg, &log_cbRespMsgSize);
	}
}