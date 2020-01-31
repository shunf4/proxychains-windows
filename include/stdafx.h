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

#ifndef __CYGWIN__
#include <strsafe.h>
#endif

#ifndef _countof
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

#endif