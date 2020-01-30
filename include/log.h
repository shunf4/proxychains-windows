#pragma once

#ifndef __LOG_H__
#define __LOG_H__

#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif
#include <wchar.h>
#include "ipc.h"

#define PXCHLOG_LEVEL_VERBOSE 600
#define PXCHLOG_LEVEL_DEBUG 500
#define PXCHLOG_LEVEL_INFO 400
#define PXCHLOG_LEVEL_WARNING 300
#define PXCHLOG_LEVEL_ERROR 200
#define PXCHLOG_LEVEL_CRITICAL 100

// Verbose level may cause stream orientation incorrect, causing undefined behaviour:
// https://www.gnu.org/software/libc/manual/html_node/Streams-and-I18N.html
#define PXCHLOG_LEVEL PXCHLOG_LEVEL_DEBUG

#define PXCHLOG(handle, level, fmt, ...) \
	do { \
		SYSTEMTIME log_time; \
		GetLocalTime(&log_time); \
		fwprintf(handle, L"[" L###level L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu " fmt L"\n", log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
		fflush(handle); \
	} while(0)

#define CYG_PXCHREMOTELOG_PID_PREFIX L"[CYGPID%5d,WINPID%5u] ["
#define CYG_PXCHREMOTELOG_PID_QUERY() DWORD log_pid = GetCurrentProcessId(); pid_t log_cyg_pid = g_bCurrentlyInWinapiCall ? -1 : cygwin_winpid_to_pid(log_pid)
#define CYG_PXCHREMOTELOG_PID_VALUE log_cyg_pid, log_pid
#define WIN_PXCHREMOTELOG_PID_PREFIX L"[PID%5u] ["
#define WIN_PXCHREMOTELOG_PID_QUERY() DWORD log_pid = GetCurrentProcessId();
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

#define PXCHREMOTELOG(handle, level, fmt, ...) \
	do { \
		PXCHREMOTELOG_PID_QUERY(); \
		if (log_pid == g_pPxchConfig->dwMasterProcessId) {\
			PXCHLOG(handle, level, fmt, ##__VA_ARGS__); \
		} else { \
			WCHAR log_szLogLine[MAX_REMOTE_LOG_BUFSIZE] = {0}; \
			SYSTEMTIME log_time; \
			IPC_MSGBUF log_msg; \
			IPC_MSGBUF log_respMsg; \
			DWORD log_cbMsgSize; \
			DWORD log_cbRespMsgSize; \
			\
			GetLocalTime(&log_time); \
			StringCchPrintfW(log_szLogLine, _countof(log_szLogLine), PXCHREMOTELOG_PID_PREFIX L###level L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu " fmt L"\n", PXCHREMOTELOG_PID_VALUE, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
			WstrToMessage(log_msg, &log_cbMsgSize, log_szLogLine); \
			IpcCommunicateWithServer(log_msg, log_cbMsgSize, log_respMsg, &log_cbRespMsgSize); \
		}  \
	} while(0)

#define PRN(fmt, ...) wprintf(L##fmt, ##__VA_ARGS__)

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_CRITICAL
#define LOGC(fmt, ...) PXCHLOG(stderr, C, fmt, ##__VA_ARGS__)
#define RLOGC(fmt, ...) PXCHREMOTELOG(stderr, C, fmt, ##__VA_ARGS__)
#else
#define LOGC(...)
#define RLOGC(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_ERROR
#define LOGE(fmt, ...) PXCHLOG(stderr, E, fmt, ##__VA_ARGS__)
#define RLOGE(fmt, ...) PXCHREMOTELOG(stderr, E, fmt, ##__VA_ARGS__)
#else
#define LOGE(...)
#define RLOGE(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_WARNING
#define LOGW(fmt, ...) PXCHLOG(stderr, W, fmt, ##__VA_ARGS__)
#define RLOGW(fmt, ...) PXCHREMOTELOG(stderr, W, fmt, ##__VA_ARGS__)
#else
#define LOGW(...)
#define RLOGW(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_INFO
#define LOGI(fmt, ...) PXCHLOG(stderr, I, fmt, ##__VA_ARGS__)
#define RLOGI(fmt, ...) PXCHREMOTELOG(stderr, I, fmt, ##__VA_ARGS__)
#else
#define LOGI(...)
#define RLOGI(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_DEBUG
#define LOGD(fmt, ...) PXCHLOG(stderr, D, fmt, ##__VA_ARGS__)
#define RLOGD(fmt, ...) PXCHREMOTELOG(stderr, D, fmt, ##__VA_ARGS__)
#else
#define LOGD(...)
#define RLOGD(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_VERBOSE
#define LOGV(fmt, ...) PXCHLOG(stderr, V, fmt, ##__VA_ARGS__)
#define RLOGV(fmt, ...) PXCHREMOTELOG(stderr, V, fmt, ##__VA_ARGS__)
#else
#define LOGV(...)
#define RLOGV(...)
#endif

#endif