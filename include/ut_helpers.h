// SPDX-License-Identifier: GPL-2.0-or-later
/* ut_helpers.h
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
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

// Replace stdlib functions to Winapi ones (So that cygwin C stdlib is not used, this is important when a Winapi call is taking place)
#define malloc(sz) HeapAlloc(GetProcessHeap(), 0, sz)
#define calloc(sz) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz)
#define relloc(ptr, sz) HeapReAlloc(GetProcessHeap(), 0, ptr, sz)
#define free(ptr) HeapFree(GetProcessHeap(), 0, ptr)
// #define uthash_bzero(a,n) ZeroMemory(a,n)
// #define memmove MoveMemory 
// #define memcpy CopyMemory

// can't indicate whether a is larger or b is larger. Fortunately uthash just wants to know whether they equal
//#define HASH_KEYCMP(a,b,n) (RtlCompareMemory(a, b, n) == n ? 0 : -1)
//#define strlen lstrlen

#ifndef __CYGWIN__
#define strdup(ptr) _strdup(ptr)
#endif

#include "uthash.h"
#include "utarray.h"
#include "utlist.h"
