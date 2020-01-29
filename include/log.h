#pragma once

#ifndef __LOG_H__
#define __LOG_H__

#include <wchar.h>

#define PXCHLOG_LEVEL_DEBUG 500
#define PXCHLOG_LEVEL_INFO 400
#define PXCHLOG_LEVEL_WARNING 300
#define PXCHLOG_LEVEL_ERROR 200
#define PXCHLOG_LEVEL_CRITICAL 100

#define PXCHLOG_LEVEL PXCHLOG_LEVEL_DEBUG

#define PXCHLOG(handle, level, fmt, ...) do { fwprintf(handle, L"[" L###level L"] " fmt L"\n", ##__VA_ARGS__); fflush(handle); } while(0)

#define PRN(fmt, ...) wprintf(L##fmt, ##__VA_ARGS__)

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_CRITICAL
#define LOGC(fmt, ...) PXCHLOG(stderr, C, fmt, ##__VA_ARGS__)
#else
#define LOGC(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_ERROR
#define LOGE(fmt, ...) PXCHLOG(stdout, E, fmt, ##__VA_ARGS__)
#else
#define LOGE(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_WARNING
#define LOGW(fmt, ...) PXCHLOG(stdout, W, fmt, ##__VA_ARGS__)
#else
#define LOGW(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_INFO
#define LOGI(fmt, ...) PXCHLOG(stdout, I, fmt, ##__VA_ARGS__)
#else
#define LOGI(...)
#endif

#if PXCHLOG_LEVEL >= PXCHLOG_LEVEL_DEBUG
#define LOGD(fmt, ...) PXCHLOG(stdout, D, fmt, ##__VA_ARGS__)
#else
#define LOGD(...)
#endif


#endif