#pragma once

#include "include_generic.h"

#ifdef __CYGWIN__
typedef __INT32_TYPE__ PXCH_INT32;
typedef __UINT32_TYPE__ PXCH_UINT32;
#else
typedef __int32 PXCH_INT32;
typedef unsigned __int32 PXCH_UINT32;
#endif


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

// In characters -- start
#define MAX_DLL_PATH_BUFSIZE 512
#define MAX_CONFIG_FILE_PATH_BUFSIZE 512
#define MAX_DLL_FILE_NAME_BUFSIZE 64
#define MAX_DLL_FUNC_NAME_BUFSIZE 64
#define MAX_IPC_PIPE_NAME_BUFSIZE 128
#define MAX_COMMAND_EXEC_PATH_BUFSIZE 512
#define MAX_COMMAND_LINE_BUFSIZE 1024
#define MAX_HOSTNAME_BUFSIZE 256
// In characters -- end

#ifdef PXCHDLL_EXPORTS
#define PXCHDLL_API __declspec(dllexport)	// Cygwin gcc also recognizes this
#else
#define PXCHDLL_API __declspec(dllimport)
#endif


#ifdef __CYGWIN__
#define IF_CYGWIN_EXIT(code) do {exit(code);} while(0)
#define IF_WIN32_EXIT(code) do {} while(0)
#else
#define IF_CYGWIN_EXIT(code) do {} while(0)
#define IF_WIN32_EXIT(code) do {exit(code);} while(0)
#endif


#ifdef __CYGWIN__
static const wchar_t g_szHookDllFileName[] = L"cygproxychains_hook.dll";
#else
static const wchar_t g_szHookDllFileName[] = L"proxychains_hook.dll";
#endif
static const wchar_t g_szMinHookDllFileName[] = L"MinHook.x64.dll";
