#pragma once
// *_generic.h : headers that are safe to be included in both types of sources: sources that uses w32api headers and sources that uses cygwin headers.
#ifndef __CYGWIN__
#pragma warning(error : 4013)
#else
#pragma GCC diagnostic error "-Wimplicit-function-declaration"
#endif

#define _WIN32_WINNT 0x0501		// Windows XP

#include <stddef.h>
#include <limits.h>

