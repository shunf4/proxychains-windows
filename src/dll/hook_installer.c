#include "hookdll_win32.h"
#include "hookdll_interior_win32.h"
#include "log_win32.h"
#include <MinHook.h>

void Win32HookConnect(void)
{
	HMODULE hWs2_32;
	LPVOID pWs2_32_WSAStartup = NULL;
	LPVOID pWs2_32_WSAConnect = NULL;
	LPVOID pWs2_32_connect = NULL;

	LoadLibraryW(L"ws2_32.dll");

	if ((hWs2_32 = GetModuleHandleW(L"ws2_32.dll"))) {
		pWs2_32_WSAStartup = GetProcAddress(hWs2_32, "WSAStartup");
		pWs2_32_WSAConnect = GetProcAddress(hWs2_32, "WSAConnect");
		pWs2_32_connect = GetProcAddress(hWs2_32, "connect");
	}

	// Another hook on ConnectEx() will take effect at WSAStartup()
	CREATE_HOOK3_IFNOTNULL(Ws2_32, WSAStartup, pWs2_32_WSAStartup);
	CREATE_HOOK3_IFNOTNULL(Ws2_32, WSAConnect, pWs2_32_WSAConnect);
	CREATE_HOOK3_IFNOTNULL(Ws2_32, connect, pWs2_32_connect);
}

void CygwinHookConnect(void)
{
	HMODULE hCygwin1;
	LPVOID pCygwin1_connect = NULL;

	LoadLibraryW(L"cygwin1.dll");

	if ((hCygwin1 = GetModuleHandleW(L"cygwin1.dll"))) { pCygwin1_connect = GetProcAddress(hCygwin1, "connect"); }

	CREATE_HOOK3_IFNOTNULL(Cygwin1, connect, pCygwin1_connect);
}
