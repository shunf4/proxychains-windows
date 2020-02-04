#pragma once

#include "defines_generic.h"

#define FP_ORIGINAL_FUNC(hooking_func_name) hooking_func_name##_SIGN(*orig_fp##hooking_func_name)

#define DECLARE_HOOK_FUNC(hooking_func_name) PXCHDLL_API hooking_func_name##_SIGN(Proxy##hooking_func_name)

#define PROXY_FUNC(hooking_func_name) FP_ORIGINAL_FUNC(hooking_func_name); PXCHDLL_API hooking_func_name##_SIGN(Proxy##hooking_func_name)

#define CREATE_HOOK(hooking_func_name) do {MH_CreateHook((LPVOID)hooking_func_name, (LPVOID)&Proxy##hooking_func_name, (LPVOID*)&orig_fp##hooking_func_name);} while(0)

#define CREATE_HOOK_ALT(prefix, hooking_func_name) do {MH_CreateHook((LPVOID)hooking_func_name, (LPVOID)&prefix##Proxy##hooking_func_name, (LPVOID*)&orig_fp##hooking_func_name);} while(0)


#define FP_ORIGINAL_FUNC2(hooked_dll_hint, hooking_func_name) hooked_dll_hint##_##hooking_func_name##_SIGN(*orig_fp##hooked_dll_hint##_##hooking_func_name)

#define DECLARE_HOOK_FUNC2(hooked_dll_hint, hooking_func_name) PXCHDLL_API hooked_dll_hint##_##hooking_func_name##_SIGN(Proxy##hooked_dll_hint##_##hooking_func_name)

#define PROXY_FUNC2(hooked_dll_hint, hooking_func_name) FP_ORIGINAL_FUNC2(hooked_dll_hint, hooking_func_name); PXCHDLL_API hooked_dll_hint##_##hooking_func_name##_SIGN(Proxy##hooked_dll_hint##_##hooking_func_name)

#define CREATE_HOOK3_IFNOTNULL(hooked_dll_hint, hooking_func_name, prehook_ptr) if (prehook_ptr) do { MH_CreateHook((LPVOID)prehook_ptr, (LPVOID)&Proxy##hooked_dll_hint##_##hooking_func_name, (LPVOID*)&orig_fp##hooked_dll_hint##_##hooking_func_name); } while(0)


#define Cygwin1_connect_SIGN(inside_identifier) int (inside_identifier) (\
	int socket,\
	const /*struct sockaddr**/ void* addr,\
	/*socklen_t*/ int socklen)

extern FP_ORIGINAL_FUNC2(Cygwin1, connect);
DECLARE_HOOK_FUNC2(Cygwin1, connect);

PXCH_UINT32 RestoreChildData();