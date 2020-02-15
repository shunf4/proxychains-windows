// SPDX-License-Identifier: GPL-2.0-or-later
/* log_generic.h
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

#define PXCH_LOG_LEVEL_VERBOSE 600
#define PXCH_LOG_LEVEL_DEBUG 500
// Release level: 400
#define PXCH_LOG_LEVEL_INFO 400
#define PXCH_LOG_LEVEL_WARNING 300
#define PXCH_LOG_LEVEL_ERROR 200
#define PXCH_LOG_LEVEL_CRITICAL 100

#ifndef PXCH_LOG_LEVEL
#ifdef _DEBUG
#define PXCH_LOG_LEVEL PXCH_LOG_LEVEL_DEBUG
#else
#define PXCH_LOG_LEVEL PXCH_LOG_LEVEL_INFO
#endif
#endif

#define PXCH_LOG_IPC_PID_PREFIX_CYG L"[CYGPID%5d,WINPID%5u] ["
#define PXCH_LOG_IPC_PID_PREFIX_WIN L"[PID%5u] ["

#ifdef __CYGWIN__
#define PXCH_LOG_IPC_PID_PREFIX  PXCH_LOG_IPC_PID_PREFIX_CYG
#else
#define PXCH_LOG_IPC_PID_PREFIX  PXCH_LOG_IPC_PID_PREFIX_WIN
#endif

#define PXCH_LOG_FMT_PREFIX(leveltag) L"[" L###leveltag L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu "
#define PXCH_LOG_IPC_FMT_PREFIX(leveltag) PXCH_LOG_IPC_PID_PREFIX L###leveltag L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu "

#define PXCH_LOG_CONCAT_FMT(leveltag, fmt) PXCH_LOG_FMT_PREFIX(leveltag) fmt L"\n"
#define PXCH_LOG_IPC_CONCAT_FMT(leveltag, fmt) PXCH_LOG_IPC_FMT_PREFIX(leveltag) fmt L"\n"

extern void pxchlog_ipc_func_e(const wchar_t* prefix_fmt, const wchar_t* ipc_prefix_fmt, const wchar_t* fmt, ...);
extern void pxchlog_ipc_func(const wchar_t* prefix_fmt, const wchar_t* ipc_prefix_fmt, const wchar_t* fmt, ...);

#define PXCH_LOG_IPC_FUNC_E(levelno, leveltag, fmt, ...) \
	do { \
		if ((g_pPxchConfig && g_pPxchConfig->dwLogLevel < levelno) || (!g_pPxchConfig && !IsDebug() && levelno >= PXCH_LOG_LEVEL_INFO)) break; \
		pxchlog_ipc_func_e(PXCH_LOG_FMT_PREFIX(leveltag), PXCH_LOG_IPC_FMT_PREFIX(leveltag), fmt L"\n", ##__VA_ARGS__); \
	} while(0)
#define PXCH_LOG_IPC_FUNC(levelno, leveltag, fmt, ...) \
	do { \
		if ((g_pPxchConfig && g_pPxchConfig->dwLogLevel < levelno) || (!g_pPxchConfig && !IsDebug() && levelno >= PXCH_LOG_LEVEL_INFO)) break; \
		pxchlog_ipc_func(PXCH_LOG_FMT_PREFIX(leveltag), PXCH_LOG_IPC_FMT_PREFIX(leveltag), fmt L"\n", ##__VA_ARGS__); \
	} while(0)

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_CRITICAL
#define FUNCIPCLOGC(fmt, ...) PXCH_LOG_IPC_FUNC_E(PXCH_LOG_LEVEL_CRITICAL, C, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGC(...)
#endif

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_ERROR
#define FUNCIPCLOGE(fmt, ...) PXCH_LOG_IPC_FUNC_E(PXCH_LOG_LEVEL_ERROR, E, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGE(...)
#endif

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_WARNING
#define FUNCIPCLOGW(fmt, ...) PXCH_LOG_IPC_FUNC(PXCH_LOG_LEVEL_WARNING, W, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGW(fmt, ...)
#endif

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_INFO
#define FUNCIPCLOGI(fmt, ...) PXCH_LOG_IPC_FUNC(PXCH_LOG_LEVEL_INFO, I, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGI(fmt, ...)
#endif

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_DEBUG
#define FUNCIPCLOGD(fmt, ...) PXCH_LOG_IPC_FUNC(PXCH_LOG_LEVEL_DEBUG, D, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGD(fmt, ...)
#endif

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_VERBOSE
#define FUNCIPCLOGV(fmt, ...) PXCH_LOG_IPC_FUNC(PXCH_LOG_LEVEL_VERBOSE, V, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGV(...)
#endif
