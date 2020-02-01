#pragma once

#ifndef __PXCH_REMOTE_H__
#define __PXCH_REMOTE_H__

#define PXCHDEBUG_REMOTEFUNCTION

#ifdef PXCHDEBUG_REMOTEFUNCTION
#define DBGCHR(ch) do { pRemoteData->fpOutputDebugStringA(pRemoteData->chDebugOutput + ((ch) - 'A') * 2); } while(0)
#define DBGCHR_GP(ch) do { if (g_pRemoteData) g_pRemoteData->fpOutputDebugStringA(g_pRemoteData->chDebugOutput + ((ch) - 'A') * 2); } while(0)
#define DBGSTR_GP(str) do { if (g_pRemoteData) g_pRemoteData->fpOutputDebugStringA(str); } while(0)
#else
#define DBGCHR(ch) do { } while(0)
#define DBGCHR_GP(ch) do {  } while(0)
#define DBGSTR_GP(str) do {  } while(0)
#endif

#endif