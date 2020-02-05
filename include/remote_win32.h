#pragma once

#include "includes_win32.h"

#define PXCHDEBUG_ODS

#ifdef PXCHDEBUG_ODS
#define DBGCHR(ch) do { pRemoteData->fpOutputDebugStringA(pRemoteData->chDebugOutput + ((ch) - 'A') * 2); } while(0)
#define DBGCHR_GP(ch) do { if (g_pRemoteData) g_pRemoteData->fpOutputDebugStringA(g_pRemoteData->chDebugOutput + ((ch) - 'A') * 2); } while(0)
#define DBGSTR_GP(str) do { if (g_pRemoteData) g_pRemoteData->fpOutputDebugStringA(str); } while(0)
#else
#define DBGCHR(ch) do { } while(0)
#define DBGCHR_GP(ch) do {  } while(0)
#define DBGSTR_GP(str) do {  } while(0)
#endif

// MSVC arranges these functions in alphabetical order
DWORD __stdcall LoadHookDll(LPVOID * pArg);
void* LoadHookDll_End(void);