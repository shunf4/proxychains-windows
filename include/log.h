#pragma once

#ifndef __LOG_H__
#define __LOG_H__

#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif
#include <wchar.h>
#include "ipc.h"
#include "common.h"

#define PXCHLOG_LEVEL_VERBOSE 600
#define PXCHLOG_LEVEL_DEBUG 500
#define PXCHLOG_LEVEL_INFO 400
#define PXCHLOG_LEVEL_WARNING 300
#define PXCHLOG_LEVEL_ERROR 200
#define PXCHLOG_LEVEL_CRITICAL 100

#define PXCHLOG_LEVEL PXCHLOG_LEVEL_DEBUG

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_CRITICAL
static SYSTEMTIME log_time;
static WCHAR log_szLogLine[MAX_REMOTE_LOG_BUFSIZE] = { 0 };
static SYSTEMTIME log_time;
static IPC_MSGBUF log_msg;
static IPC_MSGBUF log_respMsg;
static DWORD log_cbMsgSize;
static DWORD log_cbRespMsgSize;
static DWORD log_pid;

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
}
#endif
#endif

#ifdef __CYGWIN__
pid_t log_cyg_pid;
#endif

// Verbose level may cause stream orientation incorrect, causing undefined behaviour:
// https://www.gnu.org/software/libc/manual/html_node/Streams-and-I18N.html

#define PXCHLOG(level, fmt, ...) \
	do { \
		GetLocalTime(&log_time); \
		StdWprintf(STD_OUTPUT_HANDLE, L"[" L###level L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu " fmt L"\n", log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
		StdFlush(STD_OUTPUT_HANDLE); \
	} while(0)

#define PXCHLOG_E(level, fmt, ...) \
	do { \
		GetLocalTime(&log_time); \
		StdWprintf(STD_ERROR_HANDLE, L"[" L###level L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu " fmt L"\n", log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
		StdFlush(STD_ERROR_HANDLE); \
	} while(0)

#define CYG_PXCHREMOTELOG_PID_PREFIX L"[CYGPID%5d,WINPID%5u] ["
#define CYG_PXCHREMOTELOG_PID_QUERY() log_pid = GetCurrentProcessId(); log_cyg_pid = g_bCurrentlyInWinapiCall ? -1 : cygwin_winpid_to_pid(log_pid)
#define CYG_PXCHREMOTELOG_PID_VALUE log_cyg_pid, log_pid
#define WIN_PXCHREMOTELOG_PID_PREFIX L"[PID%5u] ["
#define WIN_PXCHREMOTELOG_PID_QUERY() log_pid = GetCurrentProcessId();
#define WIN_PXCHREMOTELOG_PID_VALUE log_pid

#ifdef __CYGWIN__
#define PXCHREMOTELOG_PID_PREFIX CYG_PXCHREMOTELOG_PID_PREFIX
#define PXCHREMOTELOG_PID_QUERY() CYG_PXCHREMOTELOG_PID_QUERY()
#define PXCHREMOTELOG_PID_VALUE CYG_PXCHREMOTELOG_PID_VALUE
#else
#define PXCHREMOTELOG_PID_PREFIX WIN_PXCHREMOTELOG_PID_PREFIX
#define PXCHREMOTELOG_PID_QUERY() WIN_PXCHREMOTELOG_PID_QUERY()
#define PXCHREMOTELOG_PID_VALUE WIN_PXCHREMOTELOG_PID_VALUE
#endif

#define _PXCHREMOTELOG(level, fmt, ...) do { \
	GetLocalTime(&log_time); \
	log_szLogLine[0] = L'\0'; \
	StringCchPrintfW(log_szLogLine, _countof(log_szLogLine), PXCHREMOTELOG_PID_PREFIX L###level L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu " fmt L"\n", PXCHREMOTELOG_PID_VALUE, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
	if (log_szLogLine[_countof(log_szLogLine) - 2]) log_szLogLine[_countof(log_szLogLine) - 2] = L'\n'; \
	log_szLogLine[_countof(log_szLogLine) - 1] = L'\0'; \
	WstrToMessage(log_msg, &log_cbMsgSize, log_szLogLine); \
	IpcCommunicateWithServer(log_msg, log_cbMsgSize, log_respMsg, &log_cbRespMsgSize); \
} while(0)

#define PXCHREMOTELOG(level, fmt, ...) \
	do { \
		PXCHREMOTELOG_PID_QUERY(); \
		if (log_pid == g_pPxchConfig->dwMasterProcessId) {\
			PXCHLOG(level, fmt, ##__VA_ARGS__); \
		} else { \
			_PXCHREMOTELOG(level, fmt, ##__VA_ARGS__); \
		} \
	} while(0)

#define PXCHREMOTELOG_E(level, fmt, ...) \
	do { \
		PXCHREMOTELOG_PID_QUERY(); \
		if (log_pid == g_pPxchConfig->dwMasterProcessId) {\
			PXCHLOG_E(level, fmt, ##__VA_ARGS__); \
		} else { \
			_PXCHREMOTELOG(level, fmt, ##__VA_ARGS__); \
		} \
	} while(0)

#define PRN(fmt, ...) wprintf(L##fmt, ##__VA_ARGS__)

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_CRITICAL
#define LOGC(fmt, ...) PXCHLOG_E(C, fmt, ##__VA_ARGS__)
#define RLOGC(fmt, ...) PXCHREMOTELOG_E(C, fmt, ##__VA_ARGS__)
#else
#define LOGC(...)
#define RLOGC(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_ERROR
#define LOGE(fmt, ...) PXCHLOG_E(E, fmt, ##__VA_ARGS__)
#define RLOGE(fmt, ...) PXCHREMOTELOG_E(E, fmt, ##__VA_ARGS__)
#else
#define LOGE(...)
#define RLOGE(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_WARNING
#define LOGW(fmt, ...) PXCHLOG(W, fmt, ##__VA_ARGS__)
#define RLOGW(fmt, ...) PXCHREMOTELOG(W, fmt, ##__VA_ARGS__)
#else
#define LOGW(...)
#define RLOGW(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_INFO
#define LOGI(fmt, ...) PXCHLOG(I, fmt, ##__VA_ARGS__)
#define RLOGI(fmt, ...) PXCHREMOTELOG(I, fmt, ##__VA_ARGS__)
#else
#define LOGI(...)
#define RLOGI(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_DEBUG
#define LOGD(fmt, ...) PXCHLOG(D, fmt, ##__VA_ARGS__)
#define RLOGD(fmt, ...) PXCHREMOTELOG(D, fmt, ##__VA_ARGS__)
#else
#define LOGD(...)
#define RLOGD(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_VERBOSE
#define LOGV(fmt, ...) PXCHLOG(V, fmt, ##__VA_ARGS__)
#define RLOGV(fmt, ...) PXCHREMOTELOG(V, fmt, ##__VA_ARGS__)
#else
#define LOGV(...)
#define RLOGV(...)
#endif

#endif