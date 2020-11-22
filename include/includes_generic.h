// SPDX-License-Identifier: GPL-2.0-or-later
/* includes_generic.h
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
// *_generic.h : headers that are safe to be included in both types of sources: sources that uses w32api headers and sources that uses cygwin headers.
#ifndef __CYGWIN__
// 'function' undefined; assuming extern returning int
#pragma warning(error : 4013)
// frame pointer register 'ebp' modified by inline assembly code
#pragma warning(disable : 4731)

#else
#pragma GCC diagnostic error "-Wimplicit-function-declaration"
#endif

#ifdef __CYGWIN__
#define _POSIX_C_SOURCE 200809L
#endif

#define _WIN32_WINNT 0x0502		// Windows XP SP2
// #define _WIN32_WINNT 0x0600		// Windows Vista

#include <stddef.h>
#include <limits.h>

