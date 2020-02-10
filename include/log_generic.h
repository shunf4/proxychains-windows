#pragma once

#define PXCH_LOG_LEVEL_VERBOSE 600
#define PXCH_LOG_LEVEL_DEBUG 500
// Release level: 400
#define PXCH_LOG_LEVEL_INFO 400
#define PXCH_LOG_LEVEL_WARNING 300
#define PXCH_LOG_LEVEL_ERROR 200
#define PXCH_LOG_LEVEL_CRITICAL 100

#ifndef PXCH_LOG_LEVEL
#define PXCH_LOG_LEVEL PXCH_LOG_LEVEL_DEBUG
#endif

#define PXCH_LOG_IPC_PID_PREFIX_CYG L"[CYGPID%5d,WINPID%5u] ["
#define PXCH_LOG_IPC_PID_PREFIX_WIN L"[PID%5u] ["

#ifdef __CYGWIN__
#define PXCH_LOG_IPC_PID_PREFIX  PXCH_LOG_IPC_PID_PREFIX_CYG
#else
#define PXCH_LOG_IPC_PID_PREFIX  PXCH_LOG_IPC_PID_PREFIX_WIN
#endif

#define PXCH_LOG_FMT_PREFIX(level) L"[" L###level L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu "
#define PXCH_LOG_IPC_FMT_PREFIX(level) PXCH_LOG_IPC_PID_PREFIX L###level L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu "

#define PXCH_LOG_CONCAT_FMT(level, fmt) PXCH_LOG_FMT_PREFIX(level) fmt L"\n"
#define PXCH_LOG_IPC_CONCAT_FMT(level, fmt) PXCH_LOG_IPC_FMT_PREFIX(level) fmt L"\n"

extern void pxchlog_ipc_func_e(const wchar_t* prefix_fmt, const wchar_t* ipc_prefix_fmt, const wchar_t* fmt, ...);
extern void pxchlog_ipc_func(const wchar_t* prefix_fmt, const wchar_t* ipc_prefix_fmt, const wchar_t* fmt, ...);

#define PXCH_LOG_IPC_FUNC_E(level, fmt, ...) pxchlog_ipc_func_e(PXCH_LOG_FMT_PREFIX(level), PXCH_LOG_IPC_FMT_PREFIX(level), fmt L"\n", ##__VA_ARGS__)
#define PXCH_LOG_IPC_FUNC(level, fmt, ...) pxchlog_ipc_func(PXCH_LOG_FMT_PREFIX(level), PXCH_LOG_IPC_FMT_PREFIX(level), fmt L"\n", ##__VA_ARGS__)

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_CRITICAL
#define FUNCIPCLOGC(fmt, ...) PXCH_LOG_IPC_FUNC_E(C, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGC(...)
#endif

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_ERROR
#define FUNCIPCLOGE(fmt, ...) PXCH_LOG_IPC_FUNC_E(E, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGE(...)
#endif

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_WARNING
#define FUNCIPCLOGW(fmt, ...) PXCH_LOG_IPC_FUNC(W, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGW(fmt, ...)
#endif

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_INFO
#define FUNCIPCLOGI(fmt, ...) PXCH_LOG_IPC_FUNC(I, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGI(fmt, ...)
#endif

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_DEBUG
#define FUNCIPCLOGD(fmt, ...) PXCH_LOG_IPC_FUNC(D, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGD(fmt, ...)
#endif

#if PXCH_LOG_LEVEL >= PXCH_LOG_LEVEL_VERBOSE
#define FUNCIPCLOGV(fmt, ...) PXCH_LOG_IPC_FUNC(V, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGV(...)
#endif
