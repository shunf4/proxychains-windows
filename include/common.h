#pragma once

#ifndef __COMMON_H__
#define __COMMON_H__

#include "stdafx.h"

#define MAX_ERROR_MESSAGE_BUFSIZE 256
#define MAX_FWPRINTF_BUFSIZE 256
extern WCHAR szErrorMessage[MAX_ERROR_MESSAGE_BUFSIZE];

PWCHAR FormatErrorToStr(DWORD dwError);
void PrintErrorToFile(FILE* f, DWORD dwError);
VOID StdWprintf(DWORD dwStdHandle, const WCHAR* fmt, ...);
VOID StdFlush(DWORD dwStdHandle);

#endif