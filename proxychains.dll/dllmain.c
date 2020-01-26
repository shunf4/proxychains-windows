#include <sdkddkver.h>
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <MinHook.h>
#include <tchar.h>
#include <strsafe.h>
#include <stdlib.h>

#include "proxychains_struct.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook-x64-v141-mdd.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v141-mdd.lib")
#endif

#define CreateProcessA_SIGN(name) BOOL (WINAPI name)(\
	LPCSTR lpApplicationName,\
	LPSTR lpCommandLine,\
	LPSECURITY_ATTRIBUTES lpProcessAttributes,\
	LPSECURITY_ATTRIBUTES lpThreadAttributes,\
	BOOL bInheritHandles,\
	DWORD dwCreationFlags,\
	LPVOID lpEnvironment,\
	LPCSTR lpCurrentDirectory,\
	LPSTARTUPINFOA lpStartupInfo,\
	LPPROCESS_INFORMATION lpProcessInformation)

#define CreateProcessW_SIGN(name) BOOL (WINAPI name)(\
	LPCWSTR lpApplicationName,\
	LPWSTR lpCommandLine,\
	LPSECURITY_ATTRIBUTES lpProcessAttributes,\
	LPSECURITY_ATTRIBUTES lpThreadAttributes,\
	BOOL bInheritHandles,\
	DWORD dwCreationFlags,\
	LPVOID lpEnvironment,\
	LPCWSTR lpCurrentDirectory,\
	LPSTARTUPINFOW lpStartupInfo,\
	LPPROCESS_INFORMATION lpProcessInformation)

#define FP_ORIGINAL_FUNC(name) name##_SIGN(*fp##name);
#define PROXY_FUNC(name) FP_ORIGINAL_FUNC(name); name##_SIGN(Proxy##name)
#define CREATE_HOOK(name) do {MH_CreateHook((LPVOID)&name, (LPVOID)&Proxy##name, (LPVOID*)&fp##name);} while(0)

PROXYCHAINS_CONFIG* pPxchConfig;

void MyPrintError(DWORD dwError)
{
	BOOL formatOk;
	HLOCAL hLocalBuffer;
	HMODULE hDll;


	DWORD neutralLocale = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
	formatOk = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, neutralLocale, (PTSTR)&hLocalBuffer, 0, NULL);
	if (formatOk) goto after_fmt;

	hDll = LoadLibraryEx(_T("netmsg.dll"), NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (hDll != NULL) {
		formatOk = FormatMessage(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, hDll, dwError, neutralLocale, (PTSTR)&hLocalBuffer, 0, NULL);
		FreeLibrary(hDll);
	}

after_fmt:
	if (formatOk && hLocalBuffer != NULL) {
		PCTSTR buf = (PCTSTR)LocalLock(hLocalBuffer);
		_ftprintf(stderr, _T("Error %ld: %s\n"), dwError, buf);
		LocalFree(hLocalBuffer);
	}
	else {
		_ftprintf(stderr, _T("Error %ld: Unknown Error.\n"), dwError);
	}
}

DWORD RemoteCopyExecute(HANDLE hProcess, INJECT_REMOTE_DATA* pRemoteData)
{
	void* pCode = LoadHookDll;
	void* pAfterCode = LoadHookDll_End;
	void* pTargetBuf;
	LPTHREAD_START_ROUTINE pTargetCode;
	void* pTargetData;
	size_t cbCodeSize = ((char*)pAfterCode - (char*)pCode);
	size_t cbCodeSizeAligned = (cbCodeSize + (sizeof(LONG_PTR) - 1)) & ~(sizeof(LONG_PTR) - 1);
	size_t cbWritten;
	size_t cbRead;
	DWORD dwErrorCode;
	DWORD dwReturn;
	HANDLE hRemoteThread;

	if (*(BYTE*)pCode == 0xE9) {
		_ftprintf(stderr, _T("Function body is a JMP instruction! This is usually caused by \"incremental linking\". Try to disable that.\n"));
		return ERROR_INVALID_FUNCTION;
	}

	// Allocate memory (code + data) in remote process
	pTargetBuf = VirtualAllocEx(hProcess, NULL, cbCodeSizeAligned + sizeof(INJECT_REMOTE_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pTargetBuf) goto err_alloc;

	// Write code
	pTargetCode = pTargetBuf;
	if (!WriteProcessMemory(hProcess, pTargetCode, pCode, cbCodeSize, &cbWritten) || cbWritten != cbCodeSize) goto err_write_code;

	// Write data
	pTargetData = (char *)pTargetBuf + cbCodeSizeAligned;
	if (!WriteProcessMemory(hProcess, pTargetData, pRemoteData, sizeof(INJECT_REMOTE_DATA), &cbWritten) || cbWritten != sizeof(INJECT_REMOTE_DATA)) goto err_write_data;

	// Create remote thread in target process to execute the code
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pTargetCode, pTargetData, 0, NULL);
	if (!hRemoteThread) goto err_create_remote_thread;

	// Wait for the thread to terminate
	if ((dwReturn = WaitForSingleObject(hRemoteThread, INFINITE)) != WAIT_OBJECT_0) goto err_wait;

	// Copy back data
	if (!ReadProcessMemory(hProcess, pTargetData, pRemoteData, sizeof(INJECT_REMOTE_DATA), &cbRead) || cbRead != sizeof(INJECT_REMOTE_DATA)) goto err_read_data;

	// Validate return value
	dwReturn = -1;
	if (!GetExitCodeThread(hRemoteThread, &dwReturn)) {
		_ftprintf(stderr, _T("GetExitCodeThread() Error! %lu\n"), GetLastError());
	}
	if (dwReturn != pRemoteData->dwErrorCode) {
		_ftprintf(stderr, _T("Error: Remote thread exit code does not match the error code stored in remote data memory! %lu %lu\n"), dwReturn, pRemoteData->dwErrorCode);
	}

	return 0;


err_alloc:
	dwErrorCode = GetLastError();
	_ftprintf(stderr, _T("VirtualAllocEx() Failed!\n"));
	return dwErrorCode;

err_write_code:
	dwErrorCode = GetLastError();
	_ftprintf(stderr, _T("WriteProcessMemory() Failed to write code! cbWritten = %zu, cbCodeSize = %zu\n"), cbWritten, cbCodeSize);
	goto ret_free;

err_write_data:
	dwErrorCode = GetLastError();
	_ftprintf(stderr, _T("WriteProcessMemory() Failed to write data!\n"));
	goto ret_free;

err_create_remote_thread:
	dwErrorCode = GetLastError();
	_ftprintf(stderr, _T("CreateRemoteThread() Failed!\n"));
	goto ret_free;

err_wait:
	dwErrorCode = GetLastError();
	_ftprintf(stderr, _T("WaitForSingleObject() Failed: %lu, %lu\n"), dwReturn, dwErrorCode);
	goto ret_close;

err_read_data:
	dwErrorCode = GetLastError();
	_ftprintf(stderr, _T("ReadProcessMemory() Failed to read data!\n"));
	goto ret_close;

ret_close:
	CloseHandle(hRemoteThread);

ret_free:
	VirtualFreeEx(hProcess, pTargetBuf, 0, MEM_RELEASE);
	return dwErrorCode;
}

DWORD InjectTargetProcess(HANDLE hProcess)
{
	INJECT_REMOTE_DATA remoteData;
	DWORD dwReturn;

	CopyMemory(&remoteData.pxchConfig, pPxchConfig, sizeof(PROXYCHAINS_CONFIG));
	remoteData.dwErrorCode = -1;
	remoteData.fpFreeLibrary = FreeLibrary;
	remoteData.fpGetModuleHandle = GetModuleHandle;
	remoteData.fpGetProcAddress = GetProcAddress;
	remoteData.fpLoadLibrary = LoadLibrary;
	remoteData.fpGetLastError = GetLastError;

	StringCchCopyA(remoteData.szInitFuncName, _countof(remoteData.szInitFuncName), "InitHook");
	remoteData.uEverExecuted = 0;
	remoteData.uStructSize = sizeof(INJECT_REMOTE_DATA);

	dwReturn = RemoteCopyExecute(hProcess, &remoteData);
	if (dwReturn != 0) {
		return dwReturn;
	}

	if (remoteData.uEverExecuted == 0) {
		_ftprintf(stderr, _T("Error: Remote thread never executed!\n"));
		//return ERROR_FUNCTION_NOT_CALLED;
	}

	if (remoteData.dwErrorCode != 0) {
		_ftprintf(stderr, _T("Error: Remote thread error %lu!\n"), remoteData.dwErrorCode);
		return remoteData.dwErrorCode;
	}

	return 0;
}

PROXY_FUNC(CreateProcessA)
{
	BOOL bRet;
	DWORD dwErrorCode;
	DWORD dwReturn;
	PROCESS_INFORMATION processInformation;

	bRet = fpCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, &processInformation);
	dwErrorCode = GetLastError();

	if (lpProcessInformation) {
		CopyMemory(lpProcessInformation, &processInformation, sizeof(PROCESS_INFORMATION));
	}

	_ftprintf(stderr, _T("CreateProcessA: %S, %S\n"), lpApplicationName, lpCommandLine);

	if (!bRet) goto err_orig;

	dwReturn = InjectTargetProcess(processInformation.hProcess);
	if (!(dwCreationFlags & CREATE_SUSPENDED)) {
		ResumeThread(processInformation.hThread);
	}
	if (dwReturn != 0) goto err_inject;
	return 1;

err_orig:
	_ftprintf(stderr, _T("CreateProcessA Error: %lu, %lu\n"), bRet, dwErrorCode);
	SetLastError(dwErrorCode);
	return bRet;

err_inject:
	MyPrintError(dwReturn);
	SetLastError(dwReturn);
	return 1;
}

PROXY_FUNC(CreateProcessW)
{
	BOOL bRet;
	DWORD dwErrorCode;
	DWORD dwReturn;
	PROCESS_INFORMATION processInformation;

	bRet = fpCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, &processInformation);
	dwErrorCode = GetLastError();

	if (lpProcessInformation) {
		CopyMemory(lpProcessInformation, &processInformation, sizeof(PROCESS_INFORMATION));
	}

	_ftprintf(stderr, _T("CreateProcessW: %s, %s\n"), lpApplicationName, lpCommandLine);

	if (!bRet) goto err_orig;

	dwReturn = InjectTargetProcess(processInformation.hProcess);
	if (!(dwCreationFlags & CREATE_SUSPENDED)) {
		ResumeThread(processInformation.hThread);
	}
	if (dwReturn != 0) goto err_inject;
	return 1;

err_orig:
	_ftprintf(stderr, _T("CreateProcessW Error: %lu, %lu\n"), bRet, dwErrorCode);
	SetLastError(dwErrorCode);
	return bRet;

err_inject:
	MyPrintError(dwReturn);
	SetLastError(dwReturn);
	return 1;
}

PXCHDLL_API DWORD __stdcall InitHook(INJECT_REMOTE_DATA* pData)
{
	if (pData) pPxchConfig = &pData->pxchConfig;

	MH_Initialize();
	CREATE_HOOK(CreateProcessA);
	CREATE_HOOK(CreateProcessW);
	MH_EnableHook(MH_ALL_HOOKS);

	_ftprintf(stderr, _T("Hooked!\n"));
	return 0;
}

PXCHDLL_API void UninitHook(void)
{
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();

	_ftprintf(stderr, _T("UnHooked!\n"));
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		_ftprintf(stderr, _T("DLL Attached!\n"));
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		;
	}

	return TRUE;
}