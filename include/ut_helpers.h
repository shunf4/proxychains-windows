#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#define malloc(sz) HeapAlloc(GetProcessHeap(), 0, sz)
#define calloc(sz) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz)
#define relloc(ptr, sz) HeapReAlloc(GetProcessHeap(), 0, ptr, sz)
#define free(ptr) HeapFree(GetProcessHeap(), 0, ptr)

#ifndef __CYGWIN__
#define strdup(ptr) _strdup(ptr)
#endif

#include "uthash.h"
#include "utarray.h"
#include "utlist.h"
