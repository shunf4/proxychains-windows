// SPDX-License-Identifier: GPL-2.0-or-later
/* hookdll_main.c
 * Copyright (C) 2020 Feng Shun.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2 as 
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License version 2 for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   version 2 along with this program. If not, see
 *   <http://www.gnu.org/licenses/>.
 */
#define _CRT_SECURE_NO_WARNINGS
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#include "defines_win32.h"
#include "log_win32.h"
#include "hookdll_util_win32.h"
#include <MinHook.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include "hookdll_win32.h"

#if defined(_M_X64) || defined(__x86_64__) || !defined(__CYGWIN__)
#ifdef _DEBUG
#include "remote_func_bin_x64d.h"
#else // _DEBUG
#include "remote_func_bin_x64.h"
#endif // _DEBUG
#else // defined(_M_X64) || defined(__x86_64__) || !defined(__CYGWIN__)
static const char g_RemoteFuncX64[1];
#endif // defined(_M_X64) || defined(__x86_64__) || !defined(__CYGWIN__)

#if !(defined(_M_X64) || defined(__x86_64__)) || !defined(__CYGWIN__)
#ifdef _DEBUG
#include "remote_func_bin_x86d.h"
#else // _DEBUG
#include "remote_func_bin_x86.h"
#endif // _DEBUG
#else // !(defined(_M_X64) || defined(__x86_64__)) || !defined(__CYGWIN__)
static const char g_RemoteFuncX86[1];
#endif // !(defined(_M_X64) || defined(__x86_64__)) || !defined(__CYGWIN__)

PXCH_INJECT_REMOTE_DATA* g_pRemoteData;
PXCH_DLL_API PROXYCHAINS_CONFIG* g_pPxchConfig;
PXCH_DLL_API BOOL g_bCurrentlyInWinapiCall = FALSE;
UT_array* g_arrHeapAllocatedPointers;

// To verify that this process has its original data (not overwritten with those of parent by fork())
PXCH_DLL_API DWORD g_dwCurrentProcessIdForVerify;

DWORD RemoteCopyExecute(HANDLE hProcess, BOOL bIsX86, PXCH_INJECT_REMOTE_DATA* pRemoteData)
{
	const void* pCode;
	void* pTargetBuf;
	LPTHREAD_START_ROUTINE pTargetCode;
	void* pTargetData;
	SIZE_T cbCodeSize;
	SIZE_T cbWritten;
	SIZE_T cbRead;
	DWORD dwLastError;
	DWORD dwReturn;
	HANDLE hRemoteThread;
	DWORD dwRemoteTid;
	DWORD dwRemoteDataSize = pRemoteData->dwSize;

	// if (bIsX86) {
	// 	pCode = PXCH_CONFIG_REMOTE_FUNC_X86(g_pPxchConfig);
	// 	cbCodeSize = g_pPxchConfig->cbRemoteFuncX86Size;
	// } else {
	// 	pCode = PXCH_CONFIG_REMOTE_FUNC_X64(g_pPxchConfig);
	// 	cbCodeSize = g_pPxchConfig->cbRemoteFuncX64Size;
	// }
	if (bIsX86) {
		pCode = g_RemoteFuncX86;
		cbCodeSize = sizeof(g_RemoteFuncX86) - 1;
	} else {
		pCode = g_RemoteFuncX64;
		cbCodeSize = sizeof(g_RemoteFuncX64) - 1;
	}

	if (!cbCodeSize) return ERROR_NOT_SUPPORTED;

	IPCLOGV(L"%ls", DumpMemory(pCode, 16));

	IPCLOGV(L"CreateProcessW: Before VirtualAllocEx. %lld", (long long)cbCodeSize);

	// Allocate memory (code + data) in remote process
	pTargetBuf = VirtualAllocEx(hProcess, NULL, cbCodeSize + dwRemoteDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pTargetBuf) goto err_alloc;

	IPCLOGV(L"CreateProcessW: After VirtualAllocEx. %p", pTargetBuf);

	// Write code
	pTargetCode = pTargetBuf;
	if (!WriteProcessMemory(hProcess, pTargetCode, pCode, cbCodeSize, &cbWritten) || cbWritten != cbCodeSize) goto err_write_code;

	IPCLOGV(L"CreateProcessW: After Write Code. " WPRDW, cbWritten);

	// Write data
	pTargetData = (char *)pTargetBuf + cbCodeSize;
	if (!WriteProcessMemory(hProcess, pTargetData, pRemoteData, dwRemoteDataSize, &cbWritten) || cbWritten != dwRemoteDataSize) goto err_write_data;

	IPCLOGV(L"CreateProcessW: After Write Data. " WPRDW, cbWritten);
	IPCLOGV(L"CreateProcessW: Before CreateRemoteThread. " WPRDW, 0);

	if (!ReadProcessMemory(hProcess, pTargetData, pRemoteData, dwRemoteDataSize, &cbRead) || cbRead != dwRemoteDataSize) goto err_read_data_0;

	IPCLOGV(L"CreateProcessW: Before CreateRemoteThread(ReadProcessMemory finished). " WPRDW, 0);

	if ((g_pRemoteData ? g_pRemoteData->dwDebugDepth : 0) >= 1 && FALSE) return 0;

	// Create remote thread in target process to execute the code
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pTargetCode, pTargetData, 0, &dwRemoteTid);
	if (!hRemoteThread) goto err_create_remote_thread;

	IPCLOGV(L"CreateProcessW: After CreateRemoteThread(). Tid: " WPRDW, dwRemoteTid);

	// Wait for the thread to exit
	if ((dwReturn = WaitForSingleObject(hRemoteThread, INFINITE)) != WAIT_OBJECT_0) goto err_wait;

	IPCLOGV(L"CreateProcessW: After WaitForSingleObject(). " WPRDW, 0);
	dwReturn = -1;
	if (!GetExitCodeThread(hRemoteThread, &dwReturn)) {
		IPCLOGE(L"GetExitCodeThread() Error: %ls", FormatErrorToStr(GetLastError()));
	}

	if (dwReturn != 0) {
		IPCLOGE(L"Error: Remote thread exit code: %#lx", dwReturn);
	}

	// Copy back data
	FillMemory(pRemoteData, dwRemoteDataSize, 0xFF);
	if (!ReadProcessMemory(hProcess, pTargetData, pRemoteData, dwRemoteDataSize, &cbRead) || cbRead != dwRemoteDataSize) goto err_read_data;

	if (pRemoteData->dwEverExecuted != 1) {
		IPCLOGE(L"Error: Remote thread never executed! (%u)", pRemoteData->dwEverExecuted);
		//return ERROR_FUNCTION_NOT_CALLED;
	}

	// Validate return value
	if (dwReturn != pRemoteData->dwLastError) {
		IPCLOGE(L"Error: Remote thread exit code does not match the error code stored in remote data memory! Exit code:" WPRDW L" <=> Data Memory: %ls", dwReturn, FormatErrorToStr(pRemoteData->dwLastError));
	}

	return 0;

err_alloc:
	dwLastError = GetLastError();
	IPCLOGE(L"VirtualAllocEx() Failed: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;

err_write_code:
	dwLastError = GetLastError();
	IPCLOGE(L"WriteProcessMemory() Failed to write code(cbWritten = %zu, cbCodeSize = %zu): %ls", cbWritten, cbCodeSize, FormatErrorToStr(dwLastError));
	goto ret_free;

err_write_data:
	dwLastError = GetLastError();
	IPCLOGE(L"WriteProcessMemory() Failed to write data: %ls", FormatErrorToStr(dwLastError));
	goto ret_free;

err_create_remote_thread:
	dwLastError = GetLastError();
	IPCLOGE(L"CreateRemoteThread() Failed: %ls", FormatErrorToStr(dwLastError));
	goto ret_free;

err_wait:
	dwLastError = GetLastError();
	IPCLOGE(L"WaitForSingleObject() Failed: " WPRDW L", %ls", dwReturn, FormatErrorToStr(dwLastError));
	goto ret_close;

err_read_data_0:
	dwLastError = GetLastError();
	IPCLOGE(L"ReadProcessMemory()(First time) Failed to read data: %ls", FormatErrorToStr(dwLastError));
	goto ret_free;

err_read_data:
	dwLastError = GetLastError();
	IPCLOGE(L"ReadProcessMemory() Failed to read data(" WPRDW L"/" WPRDW L"): %ls", cbRead, dwRemoteDataSize, FormatErrorToStr(dwLastError));
	goto ret_close;

ret_close:
	CloseHandle(hRemoteThread);

ret_free:
	VirtualFreeEx(hProcess, pTargetBuf, 0, MEM_RELEASE);
	return dwLastError;
}

DWORD InjectTargetProcess(const PROCESS_INFORMATION* pPi)
{
	HANDLE hProcess;
	PXCH_INJECT_REMOTE_DATA* pRemoteData;
	DWORD dwLastError;
	DWORD dwReturn;
	DWORD dwExtraSize = PXCH_CONFIG_EXTRA_SIZE_G;
	BOOL bIsX86;
	BOOL bIsWow64 = 7;

	hProcess = pPi->hProcess;
	if (!IsWow64Process(hProcess, &bIsWow64)) goto err_wow64;
	
	if (!g_bSystemInfoInitialized) {
		GetNativeSystemInfo(&g_SystemInfo);
		g_bSystemInfoInitialized = TRUE;
	}

	bIsX86 = (g_SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL || bIsWow64);

	// Another method to inject X64 -> X86: https://github.com/OpenWireSec/metasploit/blob/master/external/source/meterpreter/source/common/arch/win/i386/base_inject.c
	if (bIsX86) {
		if (g_pPxchConfig->FunctionPointers.fpGetModuleHandleWX86 == 0) {
			IPCLOGD(L"Child is an X86(Win32) process (%u %u); function address missing: won't inject", g_SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL, bIsWow64);
			return NO_ERROR;
		} else {
			IPCLOGD(L"Child is an X86(Win32) process (%u %u).", g_SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL, bIsWow64);
		}
	} else {
		if (g_pPxchConfig->FunctionPointers.fpGetModuleHandleWX64 == 0) {
			IPCLOGD(L"Child is an X64 process; function address missing: won't inject");
			return NO_ERROR;
		} else {
			IPCLOGD(L"Child is an X64 process.");
		}
	}

	pRemoteData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PXCH_INJECT_REMOTE_DATA) + dwExtraSize);

	IPCLOGV(L"CreateProcessW: Entering InjectTargetProcess. %llu", (unsigned long long)(sizeof(*pRemoteData) + dwExtraSize));

	IPCLOGV(L"CreateProcessW: Before CopyMemory. " WPRDW, 0);

	CopyMemory(&pRemoteData->pxchConfig, g_pPxchConfig, sizeof(PROXYCHAINS_CONFIG) + dwExtraSize);

	IPCLOGV(L"CreateProcessW: After CopyMemory. " WPRDW, 0);

	pRemoteData->dwLastError = -1;
	pRemoteData->dwParentPid = GetCurrentProcessId();

	pRemoteData->dwDebugDepth = g_pRemoteData ? g_pRemoteData->dwDebugDepth + 1 : 1;

	IPCLOGV(L"CreateProcessW: After remoteData assignment. " WPRDW, 0);

	StringCchCopyA(pRemoteData->szInitFuncName, _countof(pRemoteData->szInitFuncName), bIsX86 ? PXCH_INITHOOK_SYMBOL_NAME_X86 : PXCH_INITHOOK_SYMBOL_NAME_X64);
	StringCchCopyA(pRemoteData->szCIWCVarName, _countof(pRemoteData->szCIWCVarName), "g_bCurrentlyInWinapiCall");
	CopyMemory(pRemoteData->chDebugOutputStepData, g_pRemoteData ? g_pRemoteData->chDebugOutputStepData : "A\0B\0C\0D\0E\0F\0G\0H\0I\0J\0K\0L\0M\0N\0O\0P\0Q\0R\0S\0T\0", sizeof(pRemoteData->chDebugOutputStepData));
	StringCchPrintfA(pRemoteData->chDebugOutputBuf, _countof(pRemoteData->chDebugOutputBuf), "Winpid %" PRIdword " is in step ? in remote func process", pPi->dwProcessId);
	pRemoteData->cbDebugOutputCharOffset = (PXCH_UINT32)(StrChrA(pRemoteData->chDebugOutputBuf, '?') - pRemoteData->chDebugOutputBuf);
	StringCchCopyW(pRemoteData->szCygwin1ModuleName, _countof(pRemoteData->szCygwin1ModuleName), g_pRemoteData ? g_pRemoteData->szCygwin1ModuleName : L"cygwin1.dll");
	StringCchCopyW(pRemoteData->szMsys2ModuleName, _countof(pRemoteData->szMsys2ModuleName), g_pRemoteData ? g_pRemoteData->szMsys2ModuleName : L"msys-2.0.dll");
	StringCchCopyA(pRemoteData->szCygwin1InitFuncName, _countof(pRemoteData->szCygwin1InitFuncName), g_pRemoteData ? g_pRemoteData->szCygwin1InitFuncName : "cygwin_dll_init");
	StringCchCopyW(pRemoteData->szHookDllModuleName, _countof(pRemoteData->szHookDllModuleName), g_pRemoteData ? g_pRemoteData->szHookDllModuleName : g_szHookDllFileName);
	pRemoteData->dwEverExecuted = 0;
	pRemoteData->dwSize = sizeof(PXCH_INJECT_REMOTE_DATA) + dwExtraSize;

	IPCLOGD(L"%ls", pRemoteData->pxchConfig.szHookDllPath);

	IPCLOGV(L"CreateProcessW: After StringCchCopy. " WPRDW, 0);

	dwReturn = RemoteCopyExecute(hProcess, bIsX86, pRemoteData);

	if (dwReturn != 0) goto error;
	IPCLOGV(L"CreateProcessW: After RemoteCopyExecute. " WPRDW, 0);

	if (pRemoteData->dwEverExecuted == 0) {
		IPCLOGE(L"Error: Remote thread never executed!");
		dwReturn = ERROR_FUNCTION_NOT_CALLED;
		// goto error;
	}

	if (pRemoteData->dwLastError != 0) {
		IPCLOGE(L"Error: Remote thread error: %ls!", FormatErrorToStr(pRemoteData->dwLastError));
		dwReturn = pRemoteData->dwLastError;
		goto error;
	}

	HeapFree(GetProcessHeap(), 0, pRemoteData);
	return 0;

err_wow64:
	dwLastError = GetLastError();
	IPCLOGE(L"IsWow64Process() Failed: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;

error:
	HeapFree(GetProcessHeap(), 0, pRemoteData);
	return dwReturn;
}

PXCH_DLL_API DWORD __stdcall InitHookForMain(PROXYCHAINS_CONFIG* pPxchConfig)
{
	MH_Initialize();
	// CREATE_HOOK(CreateProcessA);
	CREATE_HOOK(CreateProcessW);
	// CREATE_HOOK(CreateProcessAsUserW);
	MH_EnableHook(MH_ALL_HOOKS);

	LOGD(L"Main Program Hooked!");
	return 0;
}

PXCH_DLL_API DWORD __stdcall InitHook(PXCH_INJECT_REMOTE_DATA* pRemoteData)
{
	DWORD dwLastError = 0;
	ODBGSTRLOGD(L"InitHook: begin of func");

	g_pPxchConfig = &pRemoteData->pxchConfig;
	g_pRemoteData = pRemoteData;
	ODBGSTRLOGD(L"InitHook: initialize utarray");
	utarray_new(g_arrHeapAllocatedPointers, &ut_ptr_icd);

	ODBGSTRLOGD(L"InitHook: start");

// #define PXCH_HOOK_CONDITION (g_pRemoteData->dwDebugDepth <= 3)
#define PXCH_HOOK_CONDITION (TRUE)
	if (PXCH_HOOK_CONDITION) {
		MH_Initialize();

#ifndef __CYGWIN__	// Hooking CreateProcessA under cygwin causes CreateProcessW WinError 2.
		CREATE_HOOK(CreateProcessA);
#endif
		CREATE_HOOK(CreateProcessW);
		// CREATE_HOOK(CreateProcessAsUserW);

		ODBGSTRLOGD(L"InitHook: hooked CreateProcess");

		IPCLOGD(L"(In InitHook) g_pRemoteData->dwDebugDepth = " WPRDW, g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);

		// ALL HOOKS MUST BE DONE HERE
		// AFTER fork() RESTORES DATA SEGMENT, MINHOOK IS IN UNCERTAIN STATE
		Win32HookWs2_32();
		//CygwinHook();

		ODBGSTRLOGD(L"InitHook: before MH_EnableHook");

		MH_EnableHook(MH_ALL_HOOKS);
	} else {
		IPCLOGD(L"(In InitHook) g_pRemoteData->dwDebugDepth = " WPRDW L", skipping hooking", g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);
	}
	
	ODBGSTRLOGD(L"InitHook: after MH_EnableHook");

	dwLastError = IpcClientRegisterChildProcess();

	if (dwLastError) {
		ODBGSTRLOGD(L"InitHook: after IpcClientRegisterChildProcess, IPC Failed");
	} else {
		ODBGSTRLOGD(L"InitHook: after IpcClientRegisterChildProcess, IPC Succeed");
	}

	IPCLOGD(L"I'm WINPID " WPRDW L" Hooked!", log_pid);

	g_dwCurrentProcessIdForVerify = GetCurrentProcessId();
	ODBGSTRLOGD(L"InitHook: end");
	return 0;
}

PXCH_DLL_API void UninitHook(void)
{
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();

	IPCLOGD(L"I'm WINPID " WPRDW L" UnHooked!", log_pid);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
#ifndef __CYGWIN__
	LPVOID pvData;
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		ODBGSTRLOGD(L"Initialize TLS");
		if ((g_dwTlsIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
			return FALSE;
		}
		// No break: initailize the index for the main thread.
	case DLL_THREAD_ATTACH:
		if (g_dwTlsIndex != TLS_OUT_OF_INDEXES) {
			pvData = HeapAlloc(GetProcessHeap(), 0, PXCH_TLS_TOTAL_SIZE);
			TlsSetValue(g_dwTlsIndex, pvData);
		}

		break;
	case DLL_THREAD_DETACH:
		pvData = TlsGetValue(g_dwTlsIndex);
		HeapFree(GetProcessHeap(), 0, pvData);
		break;
	case DLL_PROCESS_DETACH:
		pvData = TlsGetValue(g_dwTlsIndex);
		HeapFree(GetProcessHeap(), 0, pvData);
		TlsFree(g_dwTlsIndex);
		break;
	}
#endif
	return TRUE;
}