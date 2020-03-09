// SPDX-License-Identifier: GPL-2.0-or-later
/* includes_win32.h
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
#include "includes_generic.h"

#include <sdkddkver.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinDef.h>
#ifndef PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <wchar.h>
#include <inttypes.h>
#include <locale.h>

#ifdef __CYGWIN__
static int __attribute__((unused)) (*newlib_vswprintf)(wchar_t*, size_t, const wchar_t*, __VALIST) = vswprintf;
static int __attribute__((unused)) (*newlib_swprintf)(wchar_t*, size_t, const wchar_t*, ...) = swprintf;
#endif
#endif

#ifdef __CYGWIN__
#define __CRT__NO_INLINE
#endif

// Include strsafe too early causes compiler to complain
#ifndef PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#include <strsafe.h>
#endif

