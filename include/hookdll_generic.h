// SPDX-License-Identifier: GPL-2.0-or-later
/* defines_generic.h
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

#include "defines_generic.h"


#define FP_ORIGINAL_FUNC(hooking_func_name) hooking_func_name##_SIGN(*orig_fp##hooking_func_name)

#define DECLARE_HOOK_FUNC(hooking_func_name) PXCH_DLL_API hooking_func_name##_SIGN(Proxy##hooking_func_name)

#define PROXY_FUNC(hooking_func_name) FP_ORIGINAL_FUNC(hooking_func_name); PXCH_DLL_API hooking_func_name##_SIGN(Proxy##hooking_func_name)

#define PXCH_HOOKED_MSG L"Hooked %ls from %p to %p, return = %d"

#define CREATE_HOOK(hooking_func_name) \
	do { \
		MH_STATUS MhStatusReturn; \
		MhStatusReturn = MH_CreateHook((LPVOID)hooking_func_name, (LPVOID)&Proxy##hooking_func_name, (LPVOID*)&orig_fp##hooking_func_name); \
		(void)MhStatusReturn; \
		FUNCIPCLOGD(PXCH_HOOKED_MSG, PREFIX_L(#hooking_func_name), &hooking_func_name, &Proxy##hooking_func_name, MhStatusReturn); \
	} while(0)

#define CREATE_HOOK_ALT(prefix, hooking_func_name) do {MH_CreateHook((LPVOID)hooking_func_name, (LPVOID)&prefix##Proxy##hooking_func_name, (LPVOID*)&orig_fp##hooking_func_name);} while(0)


#define FP_ORIGINAL_FUNC2(hooked_dll_hint, hooking_func_name) hooked_dll_hint##_##hooking_func_name##_SIGN(*orig_fp##hooked_dll_hint##_##hooking_func_name)

#define DECLARE_HOOK_FUNC2(hooked_dll_hint, hooking_func_name) PXCH_DLL_API hooked_dll_hint##_##hooking_func_name##_SIGN(Proxy##hooked_dll_hint##_##hooking_func_name)

#define PROXY_FUNC2(hooked_dll_hint, hooking_func_name) FP_ORIGINAL_FUNC2(hooked_dll_hint, hooking_func_name); PXCH_DLL_API hooked_dll_hint##_##hooking_func_name##_SIGN(Proxy##hooked_dll_hint##_##hooking_func_name)

#define CREATE_HOOK3_IFNOTNULL(hooked_dll_hint, hooking_func_name, prehook_ptr) \
	if (prehook_ptr) do { \
		MH_STATUS MhStatusReturn; \
		MhStatusReturn = MH_CreateHook((LPVOID)prehook_ptr, (LPVOID)&Proxy##hooked_dll_hint##_##hooking_func_name, (LPVOID*)&orig_fp##hooked_dll_hint##_##hooking_func_name); \
		(void)MhStatusReturn; \
		FUNCIPCLOGD(PXCH_HOOKED_MSG, PREFIX_L(#hooking_func_name) L"@" PREFIX_L(#hooked_dll_hint), prehook_ptr, &Proxy##hooked_dll_hint##_##hooking_func_name, MhStatusReturn); \
	} while(0)


#define Cygwin1_connect_SIGN(inside_identifier) int (inside_identifier) (\
	int socket,\
	const /*struct sockaddr**/ void* addr,\
	/*socklen_t*/ int socklen)

extern FP_ORIGINAL_FUNC2(Cygwin1, connect);
DECLARE_HOOK_FUNC2(Cygwin1, connect);

PXCH_UINT32 RestoreChildData();