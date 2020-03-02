// SPDX-License-Identifier: GPL-2.0-or-later
/* proxychains_helper.c
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

#include "defines_win32.h"
#include "remote_win32.h"

#ifdef __CYGWIN__
#define PREFIX_ZERO_X ""
#else
#define PREFIX_ZERO_X L"0x"
#endif

#if defined(_M_X64) || defined(__x86_64__)
#define SUFFIX_ARCH L"X64"
#else
#define SUFFIX_ARCH L"X86"
#endif

int main(int argc, const char* const* argv)
{
    if (argc != 2) return 1;
    
    if (strcmp(argv[1], "--get-winapi-func-addr") == 0) {
#if defined(_M_X64) || defined(__x86_64__)
        wprintf(L"%llX\n", 0ULL);
        wprintf(L"%llX\n", 0ULL);
        wprintf(L"%llX\n", 0ULL);
        wprintf(L"%llX\n", 0ULL);
        wprintf(L"%llX\n", 0ULL);
        wprintf(L"%llX\n", 0ULL);
#else
        wprintf(L"%llX\n", (unsigned long long)&GetModuleHandleW);
        wprintf(L"%llX\n", (unsigned long long)&LoadLibraryW);
        wprintf(L"%llX\n", (unsigned long long)&GetProcAddress);
        wprintf(L"%llX\n", (unsigned long long)&FreeLibrary);
        wprintf(L"%llX\n", (unsigned long long)&GetLastError);
        wprintf(L"%llX\n", (unsigned long long)&OutputDebugStringA);
#endif
        return 0;
    }

    if (strcmp(argv[1], "--dump-remote-function") == 0) {
        void* pCode = LoadHookDll;
        void* pAfterCode = LoadHookDll_End;
        SSIZE_T cbCodeSize;
        SSIZE_T cbCodeSizeAligned;
        SSIZE_T cb;

        if (*(BYTE*)pCode == 0xE9) {
            fwprintf(stderr, L"Warning: Remote function body is a JMP instruction! This is usually caused by \"incremental linking\". Although this is correctly handled now, there might be problems in the future. Try to disable that.\n");
            pCode = (void*)((char*)pCode + *(DWORD*)((char*)pCode + 1) + 5);
        }

        if (*(BYTE*)pAfterCode == 0xE9) {
            pAfterCode = (void*)((char*)pAfterCode + *(DWORD*)((char*)pAfterCode + 1) + 5);
        }

        cbCodeSize = ((char*)pAfterCode - (char*)pCode);
        cbCodeSizeAligned = (cbCodeSize + (sizeof(LONG_PTR) - 1)) & ~(sizeof(LONG_PTR) - 1);

        wprintf(L"static const char g_RemoteFunc" SUFFIX_ARCH L"[] = \"");

        for (cb = 0; cb < cbCodeSizeAligned; cb++) {
            wprintf(L"\\x%02hhX", ((char*)pCode)[cb]);
        }

        wprintf(L"\";\n");
        fflush(stdout);
        return 0;
    }

    return 1;
}