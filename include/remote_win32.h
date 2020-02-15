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

#include "includes_win32.h"

#define PXCHDEBUG_ODS

#if defined(PXCHDEBUG_ODS) && defined(_DEBUG)
#define DBGCHR(ch) do { pRemoteData->fpOutputDebugStringA(pRemoteData->chDebugOutput + ((ch) - 'A') * 2); } while(0)
#define DBGCHR_GP(ch) do { if (g_pRemoteData) g_pRemoteData->fpOutputDebugStringA(g_pRemoteData->chDebugOutput + ((ch) - 'A') * 2); } while(0)
#define DBGSTR_GP(str) do { if (g_pRemoteData) g_pRemoteData->fpOutputDebugStringA(str); } while(0)
#else
#define DBGCHR(ch) do { } while(0)
#define DBGCHR_GP(ch) do {  } while(0)
#define DBGSTR_GP(str) do {  } while(0)
#endif

// MSVC arranges these functions in alphabetical order
DWORD __stdcall LoadHookDll(LPVOID * pArg);
void* LoadHookDll_End(void);