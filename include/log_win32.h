// SPDX-License-Identifier: GPL-2.0-or-later
/* log_win32.h
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
#pragma once
#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif

#include "defines_win32.h"
#include "hookdll_util_ipc_win32.h"
#include "log_generic.h"
#include "tls_win32.h"

// *_early are per-process instead of per-thread, which will cause race condition, and are only used at early stages of DLL loading and hook initializing
PXCH_DLL_API  extern SYSTEMTIME log_time_early;
PXCH_DLL_API  extern wchar_t log_szLogLine_early[PXCH_LOG_IPC_BUFSIZE];
PXCH_DLL_API  extern PXCH_IPC_MSGBUF log_msg_early;
PXCH_DLL_API  extern PXCH_IPC_MSGBUF log_respMsg_early;
PXCH_DLL_API  extern PXCH_UINT32 log_cbMsgSize_early;
PXCH_DLL_API  extern PXCH_UINT32 log_cbRespMsgSize_early;
PXCH_DLL_API  extern PXCH_UINT32 log_pid_early;
PXCH_DLL_API  extern PXCH_UINT32 log_tid_early;

#ifdef __CYGWIN__
extern PXCH_UINT32 log_cygpid_early;
#endif

#ifdef __CYGWIN__
static void __attribute__((unused)) suppress_unused_variables(void)
{
	(void)log_time_early;
	(void)log_szLogLine_early;
	(void)log_time_early;
	(void)log_msg_early;
	(void)log_respMsg_early;
	(void)log_cbMsgSize_early;
	(void)log_cbRespMsgSize_early;
	(void)log_pid_early;
	(void)log_tid_early;
	(void)log_cygpid_early;
}

static void __attribute__((unused)) suppress_unused_variable(void)
{
}
#endif

// After the load of Hook DLL, they will be per-thread(in TLS), thread safe
#define log_time (*((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_LOG_TIME(g_dwTlsIndex) : &log_time_early))
#define log_szLogLine ((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_LOG_SZLOGLINE(g_dwTlsIndex) : log_szLogLine_early)
#define log_msg ((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_LOG_MSG(g_dwTlsIndex) : log_msg_early)
#define log_respMsg ((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_LOG_RESPMSG(g_dwTlsIndex) : log_respMsg_early)
#define log_cbMsgSize (*((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_LOG_CBMSGSIZE(g_dwTlsIndex) : &log_cbMsgSize_early))
#define log_cbRespMsgSize (*((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_LOG_CBRESPMSGSIZE(g_dwTlsIndex) : &log_cbRespMsgSize_early))
#define log_pid (*((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_LOG_PID(g_dwTlsIndex) : &log_pid_early))
#define log_cygpid (*((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_LOG_CYGPID(g_dwTlsIndex) : &log_cygpid_early))
#define log_tid (*((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_LOG_TID(g_dwTlsIndex) : &log_tid_early))

#define PXCH_LOG_IPC_PID_QUERY_CYG() log_pid = GetCurrentProcessId(); log_cygpid = g_bCurrentlyInWinapiCall ? -1 : cygwin_winpid_to_pid(log_pid)
#define PXCH_LOG_IPC_PID_VALUE_CYG log_cygpid, log_pid
#define PXCH_LOG_IPC_PID_QUERY_WIN() log_pid = GetCurrentProcessId();
#define PXCH_LOG_IPC_PID_VALUE_WIN log_pid

#ifdef __CYGWIN__
#define PXCH_LOG_IPC_PID_QUERY() PXCH_LOG_IPC_PID_QUERY_CYG()
#define PXCH_LOG_IPC_PID_VALUE   PXCH_LOG_IPC_PID_VALUE_CYG
#else
#define PXCH_LOG_IPC_PID_QUERY() PXCH_LOG_IPC_PID_QUERY_WIN()
#define PXCH_LOG_IPC_PID_VALUE   PXCH_LOG_IPC_PID_VALUE_WIN
#endif

#define PXCH_LOG_REAL(levelno, real_fmt, ...) \
	do { \
		if ((g_pPxchConfig && g_pPxchConfig->dwLogLevel < levelno) || (!g_pPxchConfig && !IsDebug() && levelno >= PXCH_LOG_LEVEL_INFO)) break; \
		GetLocalTime(&log_time); \
		StdWprintf(STD_OUTPUT_HANDLE, real_fmt, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
		StdFlush(STD_OUTPUT_HANDLE); \
	} while(0)

#define PXCH_LOG_REAL_E(levelno, real_fmt, ...) \
	do { \
		if ((g_pPxchConfig && g_pPxchConfig->dwLogLevel < levelno) || (!g_pPxchConfig && !IsDebug() && levelno >= PXCH_LOG_LEVEL_INFO)) break; \
		GetLocalTime(&log_time); \
		StdWprintf(STD_ERROR_HANDLE, real_fmt, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
		StdFlush(STD_ERROR_HANDLE); \
	} while(0)

#define PXCH_LOG_IPC_REAL(levelno, real_fmt, ...) \
	do { \
		if ((g_pPxchConfig && g_pPxchConfig->dwLogLevel < levelno) || (!g_pPxchConfig && !IsDebug() && levelno >= PXCH_LOG_LEVEL_INFO)) break; \
		GetLocalTime(&log_time); \
		log_szLogLine[0] = L'\0'; \
		StringCchPrintfW(log_szLogLine, PXCH_MAX_FWPRINTF_BUFSIZE, real_fmt, PXCH_LOG_IPC_PID_VALUE, log_time.wYear, log_time.wMonth, log_time.wDay, log_time.wHour, log_time.wMinute, log_time.wSecond, ##__VA_ARGS__); \
		if (log_szLogLine[PXCH_MAX_FWPRINTF_BUFSIZE - 2]) log_szLogLine[PXCH_MAX_FWPRINTF_BUFSIZE - 2] = L'\n'; \
		log_szLogLine[PXCH_MAX_FWPRINTF_BUFSIZE - 1] = L'\0'; \
		WstrToMessage(log_msg, &log_cbMsgSize, log_szLogLine); \
		IpcCommunicateWithServer(log_msg, log_cbMsgSize, log_respMsg, &log_cbRespMsgSize); \
	} while(0)

#define PXCH_LOG_IPC(levelno, leveltag, fmt, ...) \
	do { \
		if ((g_pPxchConfig && g_pPxchConfig->dwLogLevel < levelno) || (!g_pPxchConfig && !IsDebug() && levelno >= PXCH_LOG_LEVEL_INFO)) break; \
		PXCH_LOG_IPC_PID_QUERY(); \
		if (g_pPxchConfig && log_pid == g_pPxchConfig->dwMasterProcessId) {\
			PXCH_LOG_REAL(levelno, PXCH_LOG_CONCAT_FMT(leveltag, fmt), ##__VA_ARGS__); \
		} else { \
			PXCH_LOG_IPC_REAL(levelno, PXCH_LOG_IPC_CONCAT_FMT(leveltag, fmt), ##__VA_ARGS__); \
		} \
	} while(0)

#define PXCH_LOG_IPC_E(levelno, leveltag, fmt, ...) \
	do { \
		if ((g_pPxchConfig && g_pPxchConfig->dwLogLevel < levelno) || (!g_pPxchConfig && !IsDebug() && levelno >= PXCH_LOG_LEVEL_INFO)) break; \
		PXCH_LOG_IPC_PID_QUERY(); \
		if (g_pPxchConfig && log_pid == g_pPxchConfig->dwMasterProcessId) {\
			PXCH_LOG_REAL_E(levelno, PXCH_LOG_CONCAT_FMT(leveltag, fmt), ##__VA_ARGS__); \
		} else { \
			PXCH_LOG_IPC_REAL(levelno, PXCH_LOG_IPC_CONCAT_FMT(leveltag, fmt), ##__VA_ARGS__); \
		} \
	} while(0)

#define PXCH_LOG(levelno, leveltag, fmt, ...) PXCH_LOG_REAL(levelno, PXCH_LOG_CONCAT_FMT(leveltag, fmt), ##__VA_ARGS__)

#define PXCH_LOG_E(levelno, leveltag, fmt, ...) PXCH_LOG_REAL_E(levelno, PXCH_LOG_CONCAT_FMT(leveltag, fmt), ##__VA_ARGS__)

#if PXCH_LOG_LEVEL_ENABLED >= PXCH_LOG_LEVEL_CRITICAL
#define LOGC(fmt, ...) PXCH_LOG_E(PXCH_LOG_LEVEL_CRITICAL, C, fmt, ##__VA_ARGS__)
#define IPCLOGC(fmt, ...) PXCH_LOG_IPC_E(PXCH_LOG_LEVEL_CRITICAL, C, fmt, ##__VA_ARGS__)
#else
#define LOGC(...)
#define IPCLOGC(...)
#endif

#if PXCH_LOG_LEVEL_ENABLED >= PXCH_LOG_LEVEL_ERROR
#define LOGE(fmt, ...) PXCH_LOG_E(PXCH_LOG_LEVEL_ERROR, E, fmt, ##__VA_ARGS__)
#define IPCLOGE(fmt, ...) PXCH_LOG_IPC_E(PXCH_LOG_LEVEL_ERROR, E, fmt, ##__VA_ARGS__)
#else
#define LOGE(...)
#define IPCLOGE(...)
#endif

#if PXCH_LOG_LEVEL_ENABLED >= PXCH_LOG_LEVEL_WARNING
#define LOGW(fmt, ...) PXCH_LOG(PXCH_LOG_LEVEL_WARNING, W, fmt, ##__VA_ARGS__)
#define IPCLOGW(fmt, ...) PXCH_LOG_IPC(PXCH_LOG_LEVEL_WARNING, W, fmt, ##__VA_ARGS__)
#else
#define LOGW(...)
#define IPCLOGW(...)
#endif

#if PXCH_LOG_LEVEL_ENABLED >= PXCH_LOG_LEVEL_INFO
#define LOGI(fmt, ...) PXCH_LOG(PXCH_LOG_LEVEL_INFO, I, fmt, ##__VA_ARGS__)
#define IPCLOGI(fmt, ...) PXCH_LOG_IPC(PXCH_LOG_LEVEL_INFO, I, fmt, ##__VA_ARGS__)
#else
#define LOGI(...)
#define IPCLOGI(...)
#endif

#if PXCH_LOG_LEVEL_ENABLED >= PXCH_LOG_LEVEL_DEBUG
#define LOGD(fmt, ...) PXCH_LOG(PXCH_LOG_LEVEL_DEBUG, D, fmt, ##__VA_ARGS__)
#define IPCLOGD(fmt, ...) PXCH_LOG_IPC(PXCH_LOG_LEVEL_DEBUG, D, fmt, ##__VA_ARGS__)
#else
#define LOGD(...)
#define IPCLOGD(...)
#endif

#if PXCH_LOG_LEVEL_ENABLED >= PXCH_LOG_LEVEL_VERBOSE
#define LOGV(fmt, ...) PXCH_LOG(PXCH_LOG_LEVEL_VERBOSE, V, fmt, ##__VA_ARGS__)
#define IPCLOGV(fmt, ...) PXCH_LOG_IPC(PXCH_LOG_LEVEL_VERBOSE, V, fmt, ##__VA_ARGS__)
#else
#define LOGV(...)
#define IPCLOGV(...)
#endif
