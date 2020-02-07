#include "common_win32.h"
#include <WinSock2.h>

WCHAR szErrorMessage[MAX_ERROR_MESSAGE_BUFSIZE];
static WCHAR szFwprintfWbuf[MAX_FWPRINTF_BUFSIZE];
static CHAR szFwprintfBuf[MAX_FWPRINTF_BUFSIZE];
static WCHAR g_HostPrintBuf[100];

VOID StdVwprintf(DWORD dwStdHandle, const WCHAR* fmt, va_list args)
{
	HANDLE h;
	STRSAFE_LPWSTR pEnd = szFwprintfWbuf;
	int iBufSize;
	DWORD cbWritten;

	szFwprintfWbuf[0] = L'\0';
	szFwprintfBuf[0] = '\0';

#ifdef __CYGWIN__
	pEnd = szFwprintfWbuf + newlib_vswprintf(szFwprintfWbuf, _countof(szFwprintfWbuf), fmt, args);
#else
	StringCchVPrintfExW(szFwprintfWbuf, _countof(szFwprintfWbuf), &pEnd, NULL, 0, fmt, args);
#endif

	if (pEnd < szFwprintfWbuf) pEnd = szFwprintfWbuf;

	if (szFwprintfWbuf[_countof(szFwprintfWbuf) - 2]) szFwprintfWbuf[_countof(szFwprintfWbuf) - 2] = L'\n';
	szFwprintfWbuf[_countof(szFwprintfWbuf) - 1] = L'\0';
	iBufSize = WideCharToMultiByte(CP_ACP, 0, szFwprintfWbuf, (int)(pEnd - szFwprintfWbuf), szFwprintfBuf, _countof(szFwprintfBuf), NULL, NULL);
	szFwprintfBuf[_countof(szFwprintfBuf) - 1] = '\0';

	h = GetStdHandle(dwStdHandle);
	if (h && h != INVALID_HANDLE_VALUE) WriteFile(h, szFwprintfBuf, iBufSize, &cbWritten, NULL);
}

VOID StdWprintf(DWORD dwStdHandle, const WCHAR* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
	StdVwprintf(dwStdHandle, fmt, args);
    va_end(args);
}

VOID StdFlush(DWORD dwStdHandle)
{
	HANDLE h;

	h = GetStdHandle(dwStdHandle);
	if (h) FlushFileBuffers(h);
}

PWCHAR FormatErrorToStr(DWORD dwError)
{
	DWORD dwCb;
	HLOCAL hLocalBuffer;
	HMODULE hDll;

	DWORD neutralLocale = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
	dwCb = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, neutralLocale, (LPWSTR)&hLocalBuffer, 0, NULL);
	if (dwCb) goto after_fmt;

	// Might be a network error
	hDll = LoadLibraryExW(L"netmsg.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (hDll != NULL) {
		dwCb = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, hDll, dwError, neutralLocale, (LPWSTR)&hLocalBuffer, 0, NULL);
		FreeLibrary(hDll);
	}

after_fmt:
	if (dwCb && hLocalBuffer != NULL) {
		PWSTR buf = (PWSTR)LocalLock(hLocalBuffer);
		if (buf[dwCb - 1] == L'\n') {
			buf[dwCb - 1] = L'\0';
		}
		if (buf[dwCb - 2] == L'\r') {
			buf[dwCb - 2] = L'\0';
		}
		StringCchPrintfW(szErrorMessage, MAX_ERROR_MESSAGE_BUFSIZE, L"%ls(" WPRDW L")", buf, dwError);
		LocalFree(hLocalBuffer);
	}
	else {
		StringCchPrintfW(szErrorMessage, MAX_ERROR_MESSAGE_BUFSIZE, L"(" WPRDW L")", dwError);
	}
	return szErrorMessage;
}


const wchar_t* FormatHostPortToStr(const void* pHostPort, int iAddrLen)
{
	DWORD dwLen;
	dwLen = _countof(g_HostPrintBuf);
	g_HostPrintBuf[0] = L'\0';

	if (HostIsType(HOSTNAME, *(PXCH_HOST*)pHostPort)) {
		StringCchPrintfW(g_HostPrintBuf, dwLen, L"%ls%hu", ((PXCH_HOSTNAME*)pHostPort)->szValue, ntohs(((PXCH_HOSTNAME*)pHostPort)->wPort));
	} else {
		WSAAddressToStringW((struct sockaddr*)(pHostPort), iAddrLen, NULL, g_HostPrintBuf, &dwLen);
	}
	return g_HostPrintBuf;
}