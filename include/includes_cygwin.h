#pragma once
#include "include_generic.h"

#include <sys/cygwin.h>

#ifdef __CYGWIN__
#define WPRS L"%s"
#else
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

