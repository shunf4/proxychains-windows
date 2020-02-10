#include <string.h>
#include <stddef.h>
#include <stdlib.h>

// Replace stdlib functions to Winapi ones (So that cygwin C stdlib is not used, this is important when a Winapi call is taking place)
#define malloc(sz) HeapAlloc(GetProcessHeap(), 0, sz)
#define calloc(sz) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz)
#define relloc(ptr, sz) HeapReAlloc(GetProcessHeap(), 0, ptr, sz)
#define free(ptr) HeapFree(GetProcessHeap(), 0, ptr)
// #define uthash_bzero(a,n) ZeroMemory(a,n)
// #define memmove MoveMemory 
// #define memcpy CopyMemory

// can't indicate whether a is larger or b is larger. Fortunately uthash just wants to know whether they equal
//#define HASH_KEYCMP(a,b,n) (RtlCompareMemory(a, b, n) == n ? 0 : -1)
//#define strlen lstrlen

#ifndef __CYGWIN__
#define strdup(ptr) _strdup(ptr)
#endif

#include "uthash.h"
#include "utarray.h"
#include "utlist.h"
