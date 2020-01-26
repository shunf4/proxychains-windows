#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <MinHook.h>

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

#if defined _M_X64
#pragma comment(lib, "libMinHook-x64-v141-mdd.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v141-mdd.lib")
#endif

typedef int (WSAAPI* CONNECT_FUNC)(SOCKET s, const struct sockaddr* name, int namelen);

CONNECT_FUNC fpConnect = NULL;

int WSAAPI ProxyConnect(SOCKET s, const struct sockaddr* name, int namelen)
{
	int iResult;
	const char proxyIP[4] = { 127, 0, 0, 1 };
	fprintf(stderr, "Hooked connect()! %d\n", memcmp(&((reinterpret_cast<const struct sockaddr_in*>(name))->sin_addr), proxyIP, 4));

	if (name->sa_family == AF_INET && memcmp(&((reinterpret_cast<const struct sockaddr_in*>(name))->sin_addr), proxyIP, 4) == 0) {
		fprintf(stderr, "Localhost!\n");
		return fpConnect(s, name, namelen);
	}

	struct sockaddr_in proxyAddr = { 0 };
	proxyAddr.sin_family = AF_INET;
	proxyAddr.sin_port = htons(1078);
	memcpy(&proxyAddr.sin_addr, proxyIP, sizeof(proxyAddr.sin_addr));

	unsigned long origSocketBlockMode = 0;
	unsigned long destSocketBlockMode = 0;

	iResult = fpConnect(s, reinterpret_cast<const struct sockaddr*>(&proxyAddr), sizeof(proxyAddr));
	if (iResult != 0 && 0) {
		int socksError = WSAGetLastError();
		fprintf(stderr, "Connect SOCKS5 server failed: %ld\n", socksError);
		if (socksError == WSAEWOULDBLOCK)
		{
			origSocketBlockMode = 1;
			// WSAEventSelect(s, 0, 0);
			iResult = ioctlsocket(s, FIONBIO, &destSocketBlockMode);
			if (iResult != 0) {
				fprintf(stderr, "ioctlsocket() failed: %ld\n", WSAGetLastError());
				return iResult;
			}
			else {
				fprintf(stderr, "Socket set to BLOCK.\n");
				fd_set writefds;
				FD_ZERO(&writefds);
				FD_SET(s, &writefds);
				select(0 /* Ignored */, NULL, &writefds, NULL, NULL);
				fprintf(stderr, "Select - socket connected now.\n");
			}
		}
		else return iResult;
	}

	Sleep(1000);

	const int SOCKS_BUF_LEN = 1024;
	char socksSendBuf[SOCKS_BUF_LEN];
	char socksRecvBuf[SOCKS_BUF_LEN];

	// TODO: Ensure send
	// I want to connect to a SOCKS"5" server, and I only provide "1" method of authentication, which is "No auth".
	memcpy_s(socksSendBuf, SOCKS_BUF_LEN, "\05\01\00", 3);
	iResult = send(s, socksSendBuf, 3, 0);
	if (iResult != 3 && 0) {
		shutdown(s, SD_BOTH);
		fprintf(stderr, "xx1\n");
		return -1;
	}

	Sleep(1000);

	// Server: Allow "No auth".
	if (recv(s, socksRecvBuf, 2, 0) != 2 || socksRecvBuf[1] != '\00') {
		shutdown(s, SD_BOTH);
		fprintf(stderr, "Server: No auth not allowed.\n");
		return -1;
	}

	// TODO: Detect type of socket

	if (name->sa_family != AF_INET) {
		shutdown(s, SD_BOTH);
		fprintf(stderr, "Only IPv4 TCP allowed.\n");
		return -1;
	}

	// I want to connect a SOCKS"5" server, and "TCP CONNECT" a remote "IPV4" address through it as a proxy. The address & port is in `name`.
	memcpy_s(socksSendBuf, SOCKS_BUF_LEN, "\05\01\00\x01\xFF\xFF\xFF\xFF\xEE\xEE", 10);
	const struct sockaddr_in* castSockAddr = reinterpret_cast<const struct sockaddr_in*>(name);
	memcpy(socksSendBuf + 4, &(castSockAddr->sin_addr), 4);
	memcpy(socksSendBuf + 8, &(castSockAddr->sin_port), 2);

	iResult = send(s, socksSendBuf, 10, 0);
	if (iResult != 10 && 0) {
		shutdown(s, SD_BOTH);
		fprintf(stderr, "xx2\n");
		return -1;
	}

	Sleep(1000);

	iResult = recv(s, socksRecvBuf, 10, 0);
	if (iResult != 10 || socksRecvBuf[1] != '\00' || socksRecvBuf[3] != '\01') {
		shutdown(s, SD_BOTH);
		fprintf(stderr, "Server: Connection not allowed. Received bytes: %ld; received payload:\n", iResult);
		const int DISP_BUF_LEN = 1024;
		char dispBuf[DISP_BUF_LEN] = { 0 };
		char* dispBufP = dispBuf;
		for (size_t i = 0; i < 10; i++)
		{
			dispBufP += sprintf_s(dispBufP, DISP_BUF_LEN - (dispBufP - dispBuf), " %02x", ((unsigned char*)socksRecvBuf)[i]);
		}
		fprintf(stderr, dispBuf);
		fprintf(stderr, "\n");
		return -1;
	}

	fprintf(stderr, "SOCKS5 init success!\n");
	/*iResult = ioctlsocket(s, FIONBIO, &origSocketBlockMode);
	if (iResult != 0) {
		fprintf(stderr, "ioctlsocket() failed: %ld\n", WSAGetLastError());
		return iResult;
	}*/
	fprintf(stderr, "ioctlsocket() success!\n");

	return 0;
}

BOOL(WINAPI* fpCreateProcessW)(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
	);

BOOL
WINAPI
ProxyCreateProcessW(
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation
) {
	WCHAR processImageName[256];
	DWORD processImageNameLength = 256;
	QueryFullProcessImageNameW(GetCurrentProcess(), 0, processImageName, &processImageNameLength);
	fprintf(stderr, "%.*S", processImageNameLength, processImageName);
	fprintf(stderr, " Invoked CreateProcessW(%S)\n", lpCommandLine);
	return fpCreateProcessW(
		lpApplicationName,
		lpCommandLine,
		lpProcessAttributes,
		lpThreadAttributes,
		bInheritHandles,
		dwCreationFlags,
		lpEnvironment,
		lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation
	);
}

extern "C" BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		MH_Initialize();
		MH_CreateHook(&connect, &ProxyConnect, reinterpret_cast<void**>((LPVOID)&fpConnect));
		MH_CreateHook(&CreateProcessW, &ProxyCreateProcessW, reinterpret_cast<void**>((LPVOID)&fpCreateProcessW));

		MH_EnableHook(MH_ALL_HOOKS);

		// MessageBoxW(NULL, L"DLL Injected!", L"DLL Injected!", NULL);
		fprintf(stderr, "DLL Injected!\n");
	}
	break;

	case DLL_PROCESS_DETACH:
		MH_DisableHook(MH_ALL_HOOKS);
		MH_Uninitialize();
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	}
	return true;
}