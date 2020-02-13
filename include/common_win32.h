#pragma once

#include "defines_win32.h"
#include "common_generic.h"

#define MAX_ERROR_MESSAGE_BUFSIZE 256

extern wchar_t szErrorMessage[MAX_ERROR_MESSAGE_BUFSIZE];

PWCHAR FormatErrorToStr(DWORD dwError);
void StdWprintf(DWORD dwStdHandle, const WCHAR* fmt, ...);
void StdVwprintf(DWORD dwStdHandle, const WCHAR* fmt, va_list args);
void StdFlush(DWORD dwStdHandle);
void DumpMemory(const void* p, int iLength);
