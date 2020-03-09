// SPDX-License-Identifier: GPL-2.0-or-later
/* remote_win32.h
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

#define STRSAFE_NO_DEPRECATE
#include "includes_win32.h"

#if defined(_M_X64) || defined(__x86_64__)
#define FUNCTION_SUFFIX_ARCH X64
#else
#define FUNCTION_SUFFIX_ARCH X86
#endif

#define CAST_FUNC_ADDR_WITH_PTR_ARCH(pRemoteData, funcName, arch) ((Fp##funcName)((pRemoteData)->pxchConfig.FunctionPointers.fp##funcName##arch))
#define CAST_FUNC_ADDR_WITH_PTR_ARCH_X(pRemoteData, funcName, arch) CAST_FUNC_ADDR_WITH_PTR_ARCH(pRemoteData, funcName, arch)
#define CAST_FUNC_ADDR_WITH_PTR(pRemoteData, funcName) CAST_FUNC_ADDR_WITH_PTR_ARCH_X(pRemoteData, funcName, FUNCTION_SUFFIX_ARCH)
#define CAST_FUNC_ADDR(funcName) CAST_FUNC_ADDR_WITH_PTR_ARCH_X(pRemoteData, funcName, FUNCTION_SUFFIX_ARCH)

#define PXCHDEBUG_ODS

#if defined(PXCHDEBUG_ODS) && defined(_DEBUG)
#define DBGCHR(ch) do { CAST_FUNC_ADDR(OutputDebugStringA)(pRemoteData->chDebugOutputStepData + ((ch) - 'A') * 2); } while(0)
#define DBGCHR_GP(ch) do { if (g_pRemoteData) CAST_FUNC_ADDR_WITH_PTR(g_pRemoteData, OutputDebugStringA)(g_pRemoteData->chDebugOutputStepData + ((ch) - 'A') * 2); } while(0)
#define DBGSTR_GP(str) do { if (g_pRemoteData) CAST_FUNC_ADDR_WITH_PTR(g_pRemoteData, OutputDebugStringA)(str); } while(0)
#define DBGSTEPX(ch) do { \
    pRemoteData->chDebugOutputBuf[pRemoteData->cbDebugOutputCharOffset] = ch; \
    CAST_FUNC_ADDR(OutputDebugStringA)(pRemoteData->chDebugOutputBuf); \
} while(0)
#define DBGSTEP(ch) DBGSTEPX(ch)
// #define DBGSTEP(ch) do {  } while(0)
#else
#define DBGCHR(ch) do { } while(0)
#define DBGCHR_GP(ch) do {  } while(0)
#define DBGSTR_GP(str) do {  } while(0)
#define DBGSTEP(ch) do {  } while(0)
#endif

// MSVC arranges these functions in alphabetical order
DWORD __stdcall LoadHookDll(LPVOID * pArg);
void* LoadHookDll_End(void);

void __cdecl CygwinEntryDetour(void);
void* CygwinEntryDetour_End(void);
