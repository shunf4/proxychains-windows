#ifndef __STDAFX_H__
#define __STDAFX_H__

#include <sdkddkver.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinDef.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <inttypes.h>

#ifdef __CYGWIN__
// Include strsafe too early causes compiler to complain
static int __attribute__((unused)) (*newlib_vswprintf)(wchar_t*, size_t, const wchar_t*, __VALIST) = vswprintf;
#define WPRS L"%s"
#else
#include <strsafe.h>
#define WPRS L"%S"
#endif


#ifdef _LP64
#define PRIdword  "u"
#define PRIudword "u"
#else
#define PRIdword  "lu"
#define PRIudword "lu"
#endif

#define _PREFIX_L(s) L ## s
#define PREFIX_L(s) _PREFIX_L(s)

#define WPRDW L"%" PREFIX_L(PRIdword)


#ifndef _countof
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

#include "uthash.h"
#include "utarray.h"
#include "utlist.h"

#endif