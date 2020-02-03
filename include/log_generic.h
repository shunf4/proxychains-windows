#pragma once

#define PXCHLOG_IPC_BUFSIZE 256
#define PXCHLOG_ODS_BUFSIZE 256

#define PXCHLOG_IPC_PID_PREFIX_CYG L"[CYGPID%5d,WINPID%5u] ["
#define PXCHLOG_IPC_PID_PREFIX_WIN L"[PID%5u] ["

#ifdef __CYGWIN__
#define PXCHLOG_IPC_PID_PREFIX  PXCHLOG_IPC_PID_PREFIX_CYG
#else
#define PXCHLOG_IPC_PID_PREFIX  PXCHLOG_IPC_PID_PREFIX_WIN
#endif

#define PXCHLOG_FMT_PREFIX(level) L"[" L###level L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu "
#define PXCHLOG_IPC_FMT_PREFIX(level) PXCHLOG_IPC_PID_PREFIX L###level L"] %hu/%02hu/%02hu %02hu:%02hu:%02hu "

#define PXCHLOG_CONCAT_FMT(level, fmt) PXCHLOG_FMT_PREFIX(level) fmt L"\n"
#define PXCHLOG_IPC_CONCAT_FMT(level, fmt) PXCHLOG_IPC_FMT_PREFIX(level) fmt L"\n"

extern void pxchlog_ipc_func_e(const wchar_t* prefix_fmt, const wchar_t* fmt, ...);
extern void pxchlog_ipc_func(const wchar_t* prefix_fmt, const wchar_t* fmt, ...);

#define PXCHLOG_IPC_FUNC_E(level, fmt, ...) pxchlog_ipc_func_e(PXCHLOG_IPC_FMT_PREFIX(level), fmt L"\n", ##__VA_ARGS__)
#define PXCHLOG_IPC_FUNC(level, fmt, ...) pxchlog_ipc_func(PXCHLOG_IPC_FMT_PREFIX(level), fmt L"\n", ##__VA_ARGS__)

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_CRITICAL
#define FUNCIPCLOGC(fmt, ...) PXCHLOG_IPC_FUNC_E(C, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGC(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_ERROR
#define FUNCIPCLOGE(fmt, ...) PXCHLOG_IPC_FUNC_E(E, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGE(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_WARNING
#define FUNCIPCLOGW(fmt, ...) PXCHLOG_IPC_FUNC(W, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGW(fmt, ...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_INFO
#define FUNCIPCLOGI(fmt, ...) PXCHLOG_IPC_FUNC(I, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGI(fmt, ...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_DEBUG
#define FUNCIPCLOGD(fmt, ...) PXCHLOG_IPC_FUNC(D, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGD(fmt, ...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_VERBOSE
#define FUNCIPCLOGV(fmt, ...) PXCHLOG_IPC_FUNC(V, fmt, ##__VA_ARGS__)
#else
#define FUNCIPCLOGV(...)
#endif
