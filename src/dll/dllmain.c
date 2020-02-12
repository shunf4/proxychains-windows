#include "defines_win32.h"
#include "log_win32.h"
#include "remote_win32.h"
#include "hookdll_interior_win32.h"
#include <MinHook.h>
#include "hookdll_win32.h"

#ifndef __CYGWIN__
#if defined _M_X64
#if defined _DEBUG
#pragma comment(lib, "libMinHook-x64-v141-mdd.lib")
#else
// MSVC will complain older compiler
//#pragma comment(lib, "libMinHook-x64-v141-md.lib")
#pragma comment(lib, "MinHook.x64.lib")
#endif
#elif defined _M_IX86
#if defined _DEBUG
#pragma comment(lib, "libMinHook-x86-v141-mdd.lib")
#else
//#pragma comment(lib, "libMinHook-x86-v141-md.lib")
#pragma comment(lib, "MinHook.x86.lib")
#endif
#endif
#endif

PXCH_INJECT_REMOTE_DATA* g_pRemoteData;
PXCH_DLL_API PROXYCHAINS_CONFIG* g_pPxchConfig;
PXCH_DLL_API BOOL g_bCurrentlyInWinapiCall = FALSE;
PXCH_DLL_API PXCH_UINT32 g_dwTlsIndex;
UT_array* g_arrHeapAllocatedPointers;

// To verify that this process has its original data (not overwritten with those of parent by fork())
PXCH_DLL_API DWORD g_dwCurrentProcessIdForVerify;


DWORD RemoteCopyExecute(HANDLE hProcess, PXCH_INJECT_REMOTE_DATA* pRemoteData)
{
	void* pCode = LoadHookDll;
	void* pAfterCode = LoadHookDll_End;
	void* pTargetBuf;
	LPTHREAD_START_ROUTINE pTargetCode;
	void* pTargetData;
	SSIZE_T cbCodeSize;
	SSIZE_T cbCodeSizeAligned;
	SIZE_T cbWritten;
	SIZE_T cbRead;
	DWORD dwErrorCode;
	DWORD dwReturn;
	HANDLE hRemoteThread;
	DWORD dwRemoteTid;
	DWORD dwRemoteDataSize = pRemoteData->dwSize;


	IPCLOGV(L"CreateProcessW: Before Code Computation. %p %p", pCode, pAfterCode);

	if (*(BYTE*)pCode == 0xE9) {
		// LOGE(L"Function body is a JMP instruction! This is usually caused by \"incremental linking\". Try to disable that.");
		// return ERROR_INVALID_FUNCTION;
		LOGV(L"Function body is a JMP instruction! This is usually caused by \"incremental linking\". Try to disable that.");
		pCode = (void*)((char*)pCode + *(DWORD*)((char*)pCode + 1) + 5);
	}

	if (*(BYTE*)pAfterCode == 0xE9) {
		pAfterCode = (void*)((char*)pAfterCode + *(DWORD*)((char*)pAfterCode + 1) + 5);
	}

	IPCLOGV(L"CreateProcessW: Before Code Computation (After fix). %p %p", pCode, pAfterCode);

	cbCodeSize = ((char*)pAfterCode - (char*)pCode);
	cbCodeSizeAligned = (cbCodeSize + (sizeof(LONG_PTR) - 1)) & ~(sizeof(LONG_PTR) - 1);

	IPCLOGV(L"CreateProcessW: Before VirtualAllocEx. %lld %lld", cbCodeSize, cbCodeSizeAligned);

	// Allocate memory (code + data) in remote process
	pTargetBuf = VirtualAllocEx(hProcess, NULL, cbCodeSizeAligned + dwRemoteDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pTargetBuf) goto err_alloc;

	IPCLOGV(L"CreateProcessW: After VirtualAllocEx. " WPRDW, 0);

	// Write code
	pTargetCode = pTargetBuf;
	if (!WriteProcessMemory(hProcess, pTargetCode, pCode, cbCodeSize, &cbWritten) || cbWritten != cbCodeSize) goto err_write_code;

	IPCLOGV(L"CreateProcessW: After Write Code. " WPRDW, 0);

	// Write data
	pTargetData = (char *)pTargetBuf + cbCodeSizeAligned;
	if (!WriteProcessMemory(hProcess, pTargetData, pRemoteData, dwRemoteDataSize, &cbWritten) || cbWritten != dwRemoteDataSize) goto err_write_data;

	IPCLOGV(L"CreateProcessW: Before CreateRemoteThread. " WPRDW, 0);

	if (!ReadProcessMemory(hProcess, pTargetData, pRemoteData, dwRemoteDataSize, &cbRead) || cbRead != dwRemoteDataSize) goto err_read_data_0;

	IPCLOGV(L"CreateProcessW: Before CreateRemoteThread(ReadProcessMemory finished). " WPRDW, 0);

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
	if (dwReturn != pRemoteData->dwErrorCode) {
		IPCLOGE(L"Error: Remote thread exit code does not match the error code stored in remote data memory! " WPRDW L" %ls", dwReturn, FormatErrorToStr(pRemoteData->dwErrorCode));
	}

	return 0;


err_alloc:
	dwErrorCode = GetLastError();
	IPCLOGE(L"VirtualAllocEx() Failed: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;

err_write_code:
	dwErrorCode = GetLastError();
	IPCLOGE(L"WriteProcessMemory() Failed to write code(cbWritten = %zu, cbCodeSize = %zu): %ls", cbWritten, cbCodeSize, FormatErrorToStr(dwErrorCode));
	goto ret_free;

err_write_data:
	dwErrorCode = GetLastError();
	IPCLOGE(L"WriteProcessMemory() Failed to write data: %ls", FormatErrorToStr(dwErrorCode));
	goto ret_free;

err_create_remote_thread:
	dwErrorCode = GetLastError();
	IPCLOGE(L"CreateRemoteThread() Failed: %ls", FormatErrorToStr(dwErrorCode));
	goto ret_free;

err_wait:
	dwErrorCode = GetLastError();
	IPCLOGE(L"WaitForSingleObject() Failed: " WPRDW L", %ls", dwReturn, FormatErrorToStr(dwErrorCode));
	goto ret_close;

err_read_data_0:
	dwErrorCode = GetLastError();
	IPCLOGE(L"ReadProcessMemory()(First time) Failed to read data: %ls", FormatErrorToStr(dwErrorCode));
	goto ret_free;

err_read_data:
	dwErrorCode = GetLastError();
	IPCLOGE(L"ReadProcessMemory() Failed to read data(" WPRDW L"/" WPRDW L"): %ls", cbRead, dwRemoteDataSize, FormatErrorToStr(dwErrorCode));
	goto ret_close;

ret_close:
	CloseHandle(hRemoteThread);

ret_free:
	VirtualFreeEx(hProcess, pTargetBuf, 0, MEM_RELEASE);
	return dwErrorCode;
}

DWORD InjectTargetProcess(const PROCESS_INFORMATION* pPi)
{
	HANDLE hProcess;
	PXCH_INJECT_REMOTE_DATA* pRemoteData;
	DWORD dwReturn;
	DWORD dwExtraSize = PXCHCONFIG_EXTRA_SIZE_G;

	pRemoteData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PXCH_INJECT_REMOTE_DATA) + dwExtraSize);

	IPCLOGV(L"CreateProcessW: Entering InjectTargetProcess. %llu", sizeof(*pRemoteData) + dwExtraSize);

	hProcess = pPi->hProcess;
	IPCLOGV(L"CreateProcessW: Before CopyMemory. " WPRDW, 0);

	CopyMemory(&pRemoteData->pxchConfig, g_pPxchConfig, sizeof(PROXYCHAINS_CONFIG) + dwExtraSize);

	IPCLOGV(L"CreateProcessW: After CopyMemory. " WPRDW, 0);

	pRemoteData->dwErrorCode = -1;
	pRemoteData->dwParentPid = GetCurrentProcessId();
	pRemoteData->fpFreeLibrary = FreeLibrary;
	pRemoteData->fpGetModuleHandleW = GetModuleHandleW;
	pRemoteData->fpGetProcAddress = GetProcAddress;
	pRemoteData->fpLoadLibraryW = LoadLibraryW;
	pRemoteData->fpGetLastError = GetLastError;
	pRemoteData->fpOutputDebugStringA = OutputDebugStringA;
	pRemoteData->pSavedPxchConfig = NULL;
	pRemoteData->pSavedRemoteData = NULL;
	pRemoteData->dwDebugDepth = g_pRemoteData ? g_pRemoteData->dwDebugDepth + 1 : 1;

	IPCLOGV(L"CreateProcessW: After remoteData assignment. " WPRDW, 0);

	StringCchCopyA(pRemoteData->szInitFuncName, _countof(pRemoteData->szInitFuncName), g_pRemoteData ? g_pRemoteData->szInitFuncName : PXCH_INITHOOK_SYMBOL_NAME);
	StringCchCopyA(pRemoteData->szCIWCVarName, _countof(pRemoteData->szCIWCVarName), g_pRemoteData ? g_pRemoteData->szCIWCVarName : "g_bCurrentlyInWinapiCall");
	CopyMemory(pRemoteData->chDebugOutput, g_pRemoteData ? g_pRemoteData->chDebugOutput : "A\0B\0C\0D\0E\0F\0G\0H\0I\0J\0K\0L\0M\0N\0O\0P\0Q\0R\0S\0T\0", sizeof(pRemoteData->chDebugOutput));
	StringCchCopyW(pRemoteData->szCygwin1ModuleName, _countof(pRemoteData->szCygwin1ModuleName), g_pRemoteData ? g_pRemoteData->szCygwin1ModuleName : L"cygwin1.dll");
	StringCchCopyW(pRemoteData->szCygwin1ModuleName, _countof(pRemoteData->szCygwin1ModuleName), g_pRemoteData ? g_pRemoteData->szHookDllModuleName : g_szHookDllFileName);
	pRemoteData->dwEverExecuted = 0;
	pRemoteData->dwSize = sizeof(PXCH_INJECT_REMOTE_DATA) + dwExtraSize;

	IPCLOGV(L"CreateProcessW: After StringCchCopy. " WPRDW, 0);

	dwReturn = RemoteCopyExecute(hProcess, pRemoteData);

	if (dwReturn != 0) goto error;
	IPCLOGV(L"CreateProcessW: After RemoteCopyExecute. " WPRDW, 0);

	if (pRemoteData->dwEverExecuted == 0) {
		IPCLOGE(L"Error: Remote thread never executed!");
		dwReturn = ERROR_FUNCTION_NOT_CALLED;
		// goto error;
	}

	if (pRemoteData->dwErrorCode != 0) {
		IPCLOGE(L"Error: Remote thread error: %ls!", FormatErrorToStr(pRemoteData->dwErrorCode));
		dwReturn = pRemoteData->dwErrorCode;
		goto error;
	}

	return 0;

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
	DWORD dwErrorCode = 0;
	ODBGSTRLOG(L"InitHook: begin of func");

	g_pPxchConfig = &pRemoteData->pxchConfig;
	g_pRemoteData = pRemoteData;
	ODBGSTRLOG(L"InitHook: initialize utarray");
	utarray_new(g_arrHeapAllocatedPointers, &ut_ptr_icd);

	ODBGSTRLOG(L"InitHook: start");

	MH_Initialize();
	// CREATE_HOOK(CreateProcessA);
	CREATE_HOOK(CreateProcessW);
	// CREATE_HOOK(CreateProcessAsUserW);

	ODBGSTRLOG(L"InitHook: hooked CreateProcess");

	IPCLOGD(L"(In InitHook) g_pRemoteData->dwDebugDepth = " WPRDW, g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);

	Win32HookWs2_32();
	CygwinHook();

	ODBGSTRLOG(L"InitHook: before MH_EnableHook");

	if (g_pRemoteData->dwDebugDepth >= 0) {
		MH_EnableHook(MH_ALL_HOOKS);
	} else {
		IPCLOGD(L"(In InitHook) g_pRemoteData->dwDebugDepth = " WPRDW L", skipping MH_EnableHook", g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);
	}
	
	ODBGSTRLOG(L"InitHook: after MH_EnableHook");

	dwErrorCode = IpcClientRegisterChildProcess();

	if (dwErrorCode) {
		ODBGSTRLOG(L"InitHook: after IpcClientRegisterChildProcess, IPC Failed");
	} else {
		ODBGSTRLOG(L"InitHook: after IpcClientRegisterChildProcess, IPC Succeed");
	}

	IPCLOGD(L"I'm WINPID " WPRDW L" Hooked!", log_pid);

	g_dwCurrentProcessIdForVerify = GetCurrentProcessId();
	ODBGSTRLOG(L"InitHook: end");
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
	LPVOID pvData;
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		ODBGSTRLOG(L"Initialize TLS");
		if ((g_dwTlsIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
			return FALSE;
		}
		// No break: initailize the index for the main thread.
	case DLL_THREAD_ATTACH:
		pvData = HeapAlloc(GetProcessHeap(), 0, PXCH_TLS_TOTAL_SIZE);
		TlsSetValue(g_dwTlsIndex, pvData);
		ODBGSTRLOG(L"Initialized TLS: g_dwTlsIndex = " WPRDW, g_dwTlsIndex);
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

	return TRUE;
}