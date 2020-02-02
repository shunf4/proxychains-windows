#pragma once
#include "include_generic.h"

#include <sdkddkver.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinDef.h>
#ifndef PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <inttypes.h>
#include <locale.h>

#ifdef __CYGWIN__
static int __attribute__((unused)) (*newlib_vswprintf)(wchar_t*, size_t, const wchar_t*, __VALIST) = vswprintf;
#endif
#endif

#ifdef __CYGWIN__
#define __CRT__NO_INLINE
#endif

// Include strsafe too early causes compiler to complain
#ifndef PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#include <strsafe.h>
#endif