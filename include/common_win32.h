// SPDX-License-Identifier: GPL-2.0-or-later
/* common_win32.h
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
#include "common_generic.h"

PWCHAR FormatErrorToStr(DWORD dwError);
void StdWprintf(DWORD dwStdHandle, const WCHAR* fmt, ...);
void StdVwprintf(DWORD dwStdHandle, const WCHAR* fmt, va_list args);
void StdFlush(DWORD dwStdHandle);
