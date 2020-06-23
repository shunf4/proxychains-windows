// SPDX-License-Identifier: GPL-2.0-or-later
/* hookdll_util_generic.h
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

#include "defines_win32.h"
#include "tls_generic.h"
#include "hookdll_util_ipc_win32.h"

PXCH_DLL_API extern HANDLE g_hCygwinConsoleSemaphore;
extern PXCH_INJECT_REMOTE_DATA* g_pRemoteData;
PXCH_DLL_API extern const wchar_t* g_szRuleTargetDesc[3];

// *_early are per-process instead of per-thread, which will cause race condition, and are only used at early stages of DLL loading and hook initializing
PXCH_DLL_API extern wchar_t g_szDumpMemoryBuf_early[PXCH_MAX_DUMP_MEMORY_BUFSIZE];
PXCH_DLL_API extern wchar_t g_szErrorMessageBuf_early[PXCH_MAX_ERROR_MESSAGE_BUFSIZE];
PXCH_DLL_API extern wchar_t g_szFormatHostPortBuf_early[PXCH_MAX_FORMAT_HOST_PORT_BUFSIZE];

PXCH_DLL_API extern wchar_t g_szFwprintfWbuf_early[PXCH_MAX_FWPRINTF_BUFSIZE];
PXCH_DLL_API extern char g_szFwprintfBuf_early[PXCH_MAX_FWPRINTF_BUFSIZE];

// After the load of Hook DLL, they will be per-thread(in TLS), thread safe
#define g_szDumpMemoryBuf ((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_DUMP_MEMORY_BUF(g_dwTlsIndex) : g_szDumpMemoryBuf_early)
#define g_szErrorMessageBuf ((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_ERROR_MESSAGE_BUF(g_dwTlsIndex) : g_szErrorMessageBuf_early)
#define g_szFormatHostPortBuf ((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_FORMAT_HOST_PORT_BUF(g_dwTlsIndex) : g_szFormatHostPortBuf_early)
#define g_szFwprintfWbuf ((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_FORMAT_FWPRINTF_W_BUF(g_dwTlsIndex) : g_szFwprintfWbuf_early)
#define g_szFwprintfBuf ((g_dwTlsIndex != TLS_OUT_OF_INDEXES) ? PXCH_TLS_PTR_FORMAT_FWPRINTF_BUF(g_dwTlsIndex) : g_szFwprintfBuf_early)

PXCH_DLL_API const wchar_t* FormatHostPortToStr(const void* pHostPort, int iAddrLen);
PXCH_DLL_API const wchar_t* DumpMemory(const void* p, int iLength);

PXCH_DLL_API void IndexToIp(const PROXYCHAINS_CONFIG* pPxchConfig, PXCH_IP_ADDRESS* pIp, PXCH_UINT32 iIndex);
PXCH_DLL_API void IpToIndex(const PROXYCHAINS_CONFIG* pPxchConfig, PXCH_UINT32* piIndex, const PXCH_IP_ADDRESS* pIp);

void pxch_cygwin_write(int fd, const void *buf, size_t nbyte);