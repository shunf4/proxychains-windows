#pragma once
#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif

#include "common_win32.h"
#include "defines_win32.h"
#include "ipc_win32.h"
#include "log_generic.h"


#define PXCHLOG_LEVEL_VERBOSE 600
#define PXCHLOG_LEVEL_DEBUG 500
#define PXCHLOG_LEVEL_INFO 400
#define PXCHLOG_LEVEL_WARNING 300
#define PXCHLOG_LEVEL_ERROR 200
#define PXCHLOG_LEVEL_CRITICAL 100

#define PXCHLOG_LEVEL PXCHLOG_LEVEL_DEBUG

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_CRITICAL
extern SYSTEMTIME log_time;
extern WCHAR log_szLogLine[PXCHLOG_IPC_BUFSIZE];
extern SYSTEMTIME log_time;
extern IPC_MSGBUF log_msg;
extern IPC_MSGBUF log_respMsg;
extern DWORD log_cbMsgSize;
extern DWORD log_cbRespMsgSize;
extern DWORD log_pid;
extern wchar_t log_ods_buf[PXCHLOG_ODS_BUFSIZE];

#ifdef __CYGWIN__
extern pid_t log_cyg_pid;
#endif

#ifdef __CYGWIN__
static void __attribute__((unused)) suppress_unused_variables(void)
{
	(void)log_time;
	(void)log_szLogLine;
	(void)log_time;
	(void)log_msg;
	(void)log_respMsg;
	(void)log_cbMsgSize;
	(void)log_cbRespMsgSize;
	(void)log_pid;
	(void)log_cyg_pid;
}
#endif
#endif


#define PXCHLOG_IPC_PID_QUERY_CYG() log_pid = GetCurrentProcessId(); log_cyg_pid = g_bCurrentlyInWinapiCall ? -1 : cygwin_winpid_to_pid(log_pid)
#define PXCHLOG_IPC_PID_VALUE_CYG log_cyg_pid, log_pid
#define PXCHLOG_IPC_PID_QUERY_WIN() log_pid = GetCurrentProcessId();
#define PXCHLOG_IPC_PID_VALUE_WIN log_pid

#ifdef __CYGWIN__
#define PXCHLOG_IPC_PID_QUERY() PXCHLOG_IPC_PID_QUERY_CYG()
#define PXCHLOG_IPC_PID_VALUE   PXCHLOG_IPC_PID_VALUE_CYG
#else
#define PXCHLOG_IPC_PID_QUERY() PXCHLOG_IPC_PID_QUERY_WIN()
#define PXCHLOG_IPC_PID_VALUE   PXCHLOG_IPC_PID_VALUE_WIN
#endif

#define PXCHLOG_REAL(real_fmt, ...) \
	do { \
		GetLocalTime(&log_time); \
		StdWprintf(STD_OUTPUT_HANDLE, real_fmt, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
		StdFlush(STD_OUTPUT_HANDLE); \
	} while(0)

#define PXCHLOG_REAL_E(real_fmt, ...) \
	do { \
		GetLocalTime(&log_time); \
		StdWprintf(STD_ERROR_HANDLE, real_fmt, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
		StdFlush(STD_ERROR_HANDLE); \
	} while(0)

#define PXCHLOG_IPC_REAL(real_fmt, ...) do { \
	GetLocalTime(&log_time); \
	log_szLogLine[0] = L'\0'; \
	StringCchPrintfW(log_szLogLine, _countof(log_szLogLine), real_fmt, PXCHLOG_IPC_PID_VALUE, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
	if (log_szLogLine[_countof(log_szLogLine) - 2]) log_szLogLine[_countof(log_szLogLine) - 2] = L'\n'; \
	log_szLogLine[_countof(log_szLogLine) - 1] = L'\0'; \
	WstrToMessage(log_msg, &log_cbMsgSize, log_szLogLine); \
	IpcCommunicateWithServer(log_msg, log_cbMsgSize, log_respMsg, &log_cbRespMsgSize); \
} while(0)

#define PXCHLOG_IPC(level, fmt, ...) \
	do { \
		PXCHLOG_IPC_PID_QUERY(); \
		if (g_pPxchConfig && log_pid == g_pPxchConfig->dwMasterProcessId) {\
			PXCHLOG_REAL(PXCHLOG_CONCAT_FMT(level, fmt), ##__VA_ARGS__); \
		} else { \
			PXCHLOG_IPC_REAL(PXCHLOG_IPC_CONCAT_FMT(level, fmt), ##__VA_ARGS__); \
		} \
	} while(0)

#define PXCHLOG_IPC_E(level, fmt, ...) \
	do { \
		PXCHLOG_IPC_PID_QUERY(); \
		if (g_pPxchConfig && log_pid == g_pPxchConfig->dwMasterProcessId) {\
			PXCHLOG_REAL_E(PXCHLOG_CONCAT_FMT(level, fmt), ##__VA_ARGS__); \
		} else { \
			PXCHLOG_IPC_REAL(PXCHLOG_IPC_CONCAT_FMT(level, fmt), ##__VA_ARGS__); \
		} \
	} while(0)

#define PXCHLOG(level, fmt, ...) PXCHLOG_REAL(PXCHLOG_CONCAT_FMT(level, fmt), ##__VA_ARGS__)

#define PXCHLOG_E(level, fmt, ...) PXCHLOG_REAL_E(PXCHLOG_CONCAT_FMT(level, fmt), ##__VA_ARGS__)

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_DEBUG
#define ODBGSTRLOG(fmt, ...) do {StringCchPrintfW(log_ods_buf, _countof(log_ods_buf), fmt, ##__VA_ARGS__); OutputDebugStringW(log_ods_buf);} while(0)
#else
#define ODBGSTRLOG(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_CRITICAL
#define LOGC(fmt, ...) PXCHLOG_E(C, fmt, ##__VA_ARGS__)
#define IPCLOGC(fmt, ...) PXCHLOG_IPC_E(C, fmt, ##__VA_ARGS__)
#else
#define LOGC(...)
#define IPCLOGC(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_ERROR
#define LOGE(fmt, ...) PXCHLOG_E(E, fmt, ##__VA_ARGS__)
#define IPCLOGE(fmt, ...) PXCHLOG_IPC_E(E, fmt, ##__VA_ARGS__)
#else
#define LOGE(...)
#define IPCLOGE(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_WARNING
#define LOGW(fmt, ...) PXCHLOG(W, fmt, ##__VA_ARGS__)
#define IPCLOGW(fmt, ...) PXCHLOG_IPC(W, fmt, ##__VA_ARGS__)
#else
#define LOGW(...)
#define IPCLOGW(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_INFO
#define LOGI(fmt, ...) PXCHLOG(I, fmt, ##__VA_ARGS__)
#define IPCLOGI(fmt, ...) PXCHLOG_IPC(I, fmt, ##__VA_ARGS__)
#else
#define LOGI(...)
#define IPCLOGI(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_DEBUG
#define LOGD(fmt, ...) PXCHLOG(D, fmt, ##__VA_ARGS__)
#define IPCLOGD(fmt, ...) PXCHLOG_IPC(D, fmt, ##__VA_ARGS__)
#else
#define LOGD(...)
#define IPCLOGD(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_VERBOSE
#define LOGV(fmt, ...) PXCHLOG(V, fmt, ##__VA_ARGS__)
#define IPCLOGV(fmt, ...) PXCHLOG_IPC(V, fmt, ##__VA_ARGS__)
#else
#define LOGV(...)
#define IPCLOGV(...)
#endif
