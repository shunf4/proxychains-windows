#define PXCH_DO_NOT_INCLUDE_STD_HEADERS_NOW
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#include "includes_win32.h"
#include "common_win32.h"
#include <WinSock2.h>
#include "hookdll_win32.h"

#include "log_generic.h"

#ifndef __CYGWIN__
#pragma comment(lib, "Ws2_32.lib")
#endif

PROXY_FUNC2(Ws2_32, connect)
{
	// SOCKET real_s = s;
	// const struct sockaddr* real_name = name;
	int i = 0;
	int iLastError;
	i = orig_fpWs2_32_connect(s, name, namelen);
	iLastError = WSAGetLastError();
	FUNCIPCLOGI(L"ws2_32.dll connect(%d, %p, %d) called: %d", s, name, namelen, i);
	FUNCIPCLOGI(L"ws2_32.dll connect() last error: %ls", FormatErrorToStr(iLastError));
	WSASetLastError(iLastError);
	return i;
}
