// SPDX-License-Identifier: GPL-2.0-or-later
/* configure.c
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

#include <Windows.h>
#include <stdio.h>
#include <wchar.h>

#ifdef __CYGWIN__
#define PREFIX_ZERO_X ""
#else
#define PREFIX_ZERO_X L"0x"
#endif

#if defined(_M_X64) || defined(__x86_64__)
// #error "Only compile it to x86 program"
int main()
{
    wprintf(L"#define PXCH_ADDRESS_FreeLibrary        " PREFIX_ZERO_X "%p\n", NULL);
    wprintf(L"#define PXCH_ADDRESS_GetModuleHandleW   " PREFIX_ZERO_X "%p\n", NULL);
    wprintf(L"#define PXCH_ADDRESS_GetProcAddress     " PREFIX_ZERO_X "%p\n", NULL);
    wprintf(L"#define PXCH_ADDRESS_LoadLibraryW       " PREFIX_ZERO_X "%p\n", NULL);
    wprintf(L"#define PXCH_ADDRESS_GetLastError       " PREFIX_ZERO_X "%p\n", NULL);
    wprintf(L"#define PXCH_ADDRESS_OutputDebugStringA " PREFIX_ZERO_X "%p\n", NULL);
    return 0;
}
#else
int main()
{
    wprintf(L"#define PXCH_ADDRESS_FreeLibrary        " PREFIX_ZERO_X "%p\n", &FreeLibrary);
	wprintf(L"#define PXCH_ADDRESS_GetModuleHandleW   " PREFIX_ZERO_X "%p\n", &GetModuleHandleW);
	wprintf(L"#define PXCH_ADDRESS_GetProcAddress     " PREFIX_ZERO_X "%p\n", &GetProcAddress);
	wprintf(L"#define PXCH_ADDRESS_LoadLibraryW       " PREFIX_ZERO_X "%p\n", &LoadLibraryW);
	wprintf(L"#define PXCH_ADDRESS_GetLastError       " PREFIX_ZERO_X "%p\n", &GetLastError);
	wprintf(L"#define PXCH_ADDRESS_OutputDebugStringA " PREFIX_ZERO_X "%p\n", &OutputDebugStringA);
    return 0;
}
#endif