#include "stdafx.h"

#include "pxch_defines.h"
#include "pxch_hook.h"
#include "log.h"
#include "common.h"

#include <locale.h>
#include <MinHook.h>

#ifndef __CYGWIN__
#if defined _M_X64
#pragma comment(lib, "libMinHook-x64-v141-mdd.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v141-mdd.lib")
#endif
#endif

#ifdef __CYGWIN__
#include <strsafe.h>
#endif

INJECT_REMOTE_DATA* pRemoteData;
PXCHDLL_API PROXYCHAINS_CONFIG* pPxchConfig;

DWORD RemoteCopyExecute(HANDLE hProcess, INJECT_REMOTE_DATA* pRemoteData)
{
	void* pCode = LoadHookDll;
	void* pAfterCode = LoadHookDll_End;
	void* pTargetBuf;
	LPTHREAD_START_ROUTINE pTargetCode;
	void* pTargetData;
	SIZE_T cbCodeSize;
	SIZE_T cbCodeSizeAligned;
	SIZE_T cbWritten;
	SIZE_T cbRead;
	DWORD dwErrorCode;
	DWORD dwReturn;
	HANDLE hRemoteThread;

	if (*(BYTE*)pCode == 0xE9) {
		// LOGE(L"Function body is a JMP instruction! This is usually caused by \"incremental linking\". Try to disable that.");
		// return ERROR_INVALID_FUNCTION;
		LOGW(L"Function body is a JMP instruction! This is usually caused by \"incremental linking\". Try to disable that.");
		pCode = (void*)((char*)pCode + *(DWORD*)((char*)pCode + 1) + 5);
	}

	if (*(BYTE*)pAfterCode == 0xE9) {
		pAfterCode = (void*)((char*)pAfterCode + *(DWORD*)((char*)pAfterCode + 1) + 5);
	}

	cbCodeSize = ((char*)pAfterCode - (char*)pCode);
	cbCodeSizeAligned = (cbCodeSize + (sizeof(LONG_PTR) - 1)) & ~(sizeof(LONG_PTR) - 1);

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

	LOGD(L"WaitForSingleObject()...");
	// Wait for the thread to terminate
	if ((dwReturn = WaitForSingleObject(hRemoteThread, INFINITE)) != WAIT_OBJECT_0) goto err_wait;
	LOGD(L"WaitForSingleObject() Succeeded.");

	dwReturn = -1;
	if (!GetExitCodeThread(hRemoteThread, &dwReturn)) {
		LOGE(L"GetExitCodeThread() Error: %ls", FormatErrorToStr(GetLastError()));
	}
	LOGD(L"dwReturn = %lu", dwReturn);

	// Copy back data
	if (!ReadProcessMemory(hProcess, pTargetData, pRemoteData, sizeof(INJECT_REMOTE_DATA), &cbRead) || cbRead != sizeof(INJECT_REMOTE_DATA)) goto err_read_data;

	// Validate return value
	if (dwReturn != pRemoteData->dwErrorCode) {
		LOGE(L"Error: Remote thread exit code does not match the error code stored in remote data memory! %lu %ls", dwReturn, FormatErrorToStr(pRemoteData->dwErrorCode));
	}

	return 0;


err_alloc:
	dwErrorCode = GetLastError();
	LOGE(L"VirtualAllocEx() Failed: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;

err_write_code:
	dwErrorCode = GetLastError();
	LOGE(L"WriteProcessMemory() Failed to write code(cbWritten = %zu, cbCodeSize = %zu): %ls", cbWritten, cbCodeSize, FormatErrorToStr(dwErrorCode));
	goto ret_free;

err_write_data:
	dwErrorCode = GetLastError();
	LOGE(L"WriteProcessMemory() Failed to write data: %ls", FormatErrorToStr(dwErrorCode));
	goto ret_free;

err_create_remote_thread:
	dwErrorCode = GetLastError();
	LOGE(L"CreateRemoteThread() Failed: %ls", FormatErrorToStr(dwErrorCode));
	goto ret_free;

err_wait:
	dwErrorCode = GetLastError();
	LOGE(L"WaitForSingleObject() Failed: %lu, %ls", dwReturn, FormatErrorToStr(dwErrorCode));
	goto ret_close;

err_read_data:
	dwErrorCode = GetLastError();
	LOGE(L"ReadProcessMemory() Failed to read data: %ls", FormatErrorToStr(dwErrorCode));
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
	remoteData.fpGetModuleHandleW = GetModuleHandleW;
	remoteData.fpGetProcAddress = GetProcAddress;
	remoteData.fpLoadLibraryW = LoadLibraryW;
	remoteData.fpGetLastError = GetLastError;

	StringCchCopyA(remoteData.szInitFuncName, _countof(remoteData.szInitFuncName), pRemoteData ? pRemoteData->szInitFuncName : "InitHook");
	remoteData.uEverExecuted = 0;
	remoteData.uStructSize = sizeof(INJECT_REMOTE_DATA);

	dwReturn = RemoteCopyExecute(hProcess, &remoteData);
	if (dwReturn != 0) {
		return dwReturn;
	}

	if (remoteData.uEverExecuted == 0) {
		LOGE(L"Error: Remote thread never executed!");
		//return ERROR_FUNCTION_NOT_CALLED;
	}

	if (remoteData.dwErrorCode != 0) {
		LOGE(L"Error: Remote thread error: %ls!", FormatErrorToStr(remoteData.dwErrorCode));
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

	LOGI(L"CreateProcessA: %S, %S", lpApplicationName, lpCommandLine);

	if (!bRet) goto err_orig;

	dwReturn = InjectTargetProcess(processInformation.hProcess);
	if (!(dwCreationFlags & CREATE_SUSPENDED)) {
		ResumeThread(processInformation.hThread);
	}
	if (dwReturn != 0) goto err_inject;
	return 1;

err_orig:
	LOGE(L"CreateProcessA Error: %lu, %ls", bRet, FormatErrorToStr(dwErrorCode));
	SetLastError(dwErrorCode);
	return bRet;

err_inject:
	PrintErrorToFile(stderr, dwReturn);
	SetLastError(dwReturn);
	return 1;
}

PROXY_FUNC(CreateProcessW)
{
	BOOL bRet;
	DWORD dwErrorCode;
	DWORD dwReturn;
	PROCESS_INFORMATION processInformation;

	LOGI(L"CreateProcessW: %ls, %ls, lpProcessAttributes: %#llx, lpThreadAttributes: %#llx, bInheritHandles: %d, dwCreationFlags: %#lx, lpCurrentDirectory: %s", lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpCurrentDirectory);

	bRet = fpCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, &processInformation);
	dwErrorCode = GetLastError();

	if (lpProcessInformation) {
		CopyMemory(lpProcessInformation, &processInformation, sizeof(PROCESS_INFORMATION));
	}

	if (!bRet) goto err_orig;

	dwReturn = InjectTargetProcess(processInformation.hProcess);

	if (!(dwCreationFlags & CREATE_SUSPENDED)) {
		ResumeThread(processInformation.hThread);
	}
	
	if (dwReturn != 0) goto err_inject;
	return 1;

err_orig:
	LOGE(L"CreateProcessW Error: %lu, %ls", bRet, FormatErrorToStr(dwErrorCode));
	SetLastError(dwErrorCode);
	return bRet;

err_inject:
	PrintErrorToFile(stderr, dwReturn);
	SetLastError(dwReturn);
	return 1;
}

PXCHDLL_API DWORD __stdcall InitHookForMain(void)
{
	MH_Initialize();
	CREATE_HOOK(CreateProcessA);
	CREATE_HOOK(CreateProcessW);
	MH_EnableHook(MH_ALL_HOOKS);

	LOGI(L"Main Program Hooked!");
	return 0;
}

PXCHDLL_API DWORD __stdcall InitHook(INJECT_REMOTE_DATA* pData)
{
	pPxchConfig = &pData->pxchConfig;

	MH_Initialize();
	CREATE_HOOK(CreateProcessA);
	CREATE_HOOK(CreateProcessW);
	MH_EnableHook(MH_ALL_HOOKS);

	//LOGI(L"PID %lu Hooked!", GetCurrentProcessId());
	return 0;
}

PXCHDLL_API void UninitHook(void)
{
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();

	LOGI(L"PID %lu UnHooked!", GetCurrentProcessId());
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		LOGI(L"PID %lu DLL Attached!", GetCurrentProcessId());
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		;
	}

	return TRUE;
}