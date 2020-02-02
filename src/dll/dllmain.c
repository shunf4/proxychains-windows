#include "defines_win32.h"
#include "log_win32.h"
#include "remote_win32.h"
#include "hookdll_win32.h"
#include <MinHook.h>

#ifndef __CYGWIN__
#if defined _M_X64
#pragma comment(lib, "libMinHook-x64-v141-mdd.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86-v141-mdd.lib")
#endif
#endif

PXCHDLL_API HANDLE g_hIpcServerSemaphore;
INJECT_REMOTE_DATA* g_pRemoteData;
PXCHDLL_API PROXYCHAINS_CONFIG* g_pPxchConfig;
PXCHDLL_API BOOL g_bCurrentlyInWinapiCall = FALSE;

PXCH_UINT32 IpcCommunicateWithServer(const IPC_MSGBUF sendMessage, PXCH_UINT32 cbSendMessageSize, IPC_MSGBUF responseMessage, PXCH_UINT32* pcbResponseMessageSize)
{
	HANDLE hPipe;
	DWORD cbToWrite;
	DWORD cbWritten;
	DWORD dwMode;
	DWORD dwErrorCode;
	BOOL bReturn;

	*pcbResponseMessageSize = 0;
	SetMsgInvalid(responseMessage);

	DBGSTR_GP("before createfile");

	// Try to open a named pipe; wait for it if necessary
	while (1)
	{
		hPipe = CreateFileW(g_pPxchConfig->szIpcPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE) break;
		if ((dwErrorCode = GetLastError()) != ERROR_PIPE_BUSY) goto err_open_pipe;

		// Wait needed
		if (!WaitNamedPipeW(g_pPxchConfig->szIpcPipeName, 2000)) goto err_wait_pipe;
	}

	DBGSTR_GP("after createfile");

	dwMode = PIPE_READMODE_MESSAGE;
	bReturn = SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
	if (!bReturn) goto err_set_handle_state;

	DBGSTR_GP("after SetNamedPipeHandleState");

	// Request
	cbToWrite = (DWORD)cbSendMessageSize;
	bReturn = WriteFile(hPipe, sendMessage, cbToWrite, &cbWritten, NULL);
	if (!bReturn || cbToWrite != cbWritten) goto err_write;

	DBGSTR_GP("after WriteFile");

	// Read response
	bReturn = ReadFile(hPipe, responseMessage, IPC_BUFSIZE, pcbResponseMessageSize, NULL);
	if (!bReturn) goto err_read;

	DBGSTR_GP("after ReadFile");

	CloseHandle(hPipe);
	return 0;

err_open_pipe:
	// Opening pipe using CreateFileW error
	return dwErrorCode;

err_wait_pipe:
	dwErrorCode = GetLastError();
	// Waiting pipe using WaitNamedPipeW error
	goto close_ret;

err_set_handle_state:
	dwErrorCode = GetLastError();
	// SetNamedPipeHandleState() error
	goto close_ret;

err_write:
	dwErrorCode = GetLastError();
	// WriteFile() error
	dwErrorCode = (dwErrorCode == NO_ERROR ? ERROR_WRITE_FAULT : dwErrorCode);
	goto close_ret;

err_read:
	dwErrorCode = GetLastError();
	// ReadFile() error
	goto close_ret;

close_ret:
	CloseHandle(hPipe);
	return dwErrorCode;
}


DWORD IpcClientRegisterChildProcess()
{
	REPORTED_CHILD_DATA childData;
	IPC_MSGBUF chMessageBuf;
	IPC_MSGBUF chRespMessageBuf;
	DWORD cbMessageSize;
	DWORD cbRespMessageSize;
	DWORD dwErrorCode;

	childData.dwPid = GetCurrentProcessId();
	childData.pSavedPxchConfig = g_pPxchConfig;
	childData.pSavedRemoteData = g_pRemoteData;

	if ((dwErrorCode = ChildDataToMessage(chMessageBuf, &cbMessageSize, &childData)) != NO_ERROR) return dwErrorCode;
	if ((dwErrorCode = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, &cbRespMessageSize)) != NO_ERROR) return dwErrorCode;

	return 0;
}


DWORD IpcClientRestoreData()
{
	REPORTED_CHILD_DATA childData;
	IPC_MSGBUF chMessageBuf;
	IPC_MSGBUF chRespMessageBuf;
	DWORD cbMessageSize;
	DWORD cbRespMessageSize;
	DWORD dwErrorCode;

	childData.dwPid = GetCurrentProcessId();

	if (childData.dwPid == g_pPxchConfig->dwMasterProcessId) return 0;

	if ((dwErrorCode = QueryStorageToMessage(chMessageBuf, &cbMessageSize, childData.dwPid)) != NO_ERROR) return dwErrorCode;
	if ((dwErrorCode = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, &cbRespMessageSize)) != NO_ERROR) return dwErrorCode;
	if ((dwErrorCode = MessageToChildData(&childData, chRespMessageBuf, cbRespMessageSize)) != NO_ERROR) return dwErrorCode;

	IPCLOGV(L"g_pPxchConfig was %p", g_pPxchConfig);
	IPCLOGV(L"g_pRemoteData was %p", g_pRemoteData);

	if (childData.pSavedPxchConfig == NULL || childData.pSavedRemoteData == NULL) goto err_no_entry;
	g_pPxchConfig = childData.pSavedPxchConfig;
	g_pRemoteData = childData.pSavedRemoteData;

	IPCLOGV(L"g_pPxchConfig restored to %p", g_pPxchConfig);
	IPCLOGV(L"g_pRemoteData restored to %p", g_pRemoteData);
	
	return 0;

err_no_entry:
	IPCLOGE(L"Received CHILDDATA invalid");
	return ERROR_INVALID_DATA;
}

DWORD RemoteCopyExecute(HANDLE hProcess, INJECT_REMOTE_DATA* pRemoteData)
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
	pTargetBuf = VirtualAllocEx(hProcess, NULL, cbCodeSizeAligned + sizeof(INJECT_REMOTE_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pTargetBuf) goto err_alloc;

	IPCLOGV(L"CreateProcessW: After VirtualAllocEx. " WPRDW, 0);

	// Write code
	pTargetCode = pTargetBuf;
	if (!WriteProcessMemory(hProcess, pTargetCode, pCode, cbCodeSize, &cbWritten) || cbWritten != cbCodeSize) goto err_write_code;

	IPCLOGV(L"CreateProcessW: After Write Code. " WPRDW, 0);

	// Write data
	pTargetData = (char *)pTargetBuf + cbCodeSizeAligned;
	if (!WriteProcessMemory(hProcess, pTargetData, pRemoteData, sizeof(INJECT_REMOTE_DATA), &cbWritten) || cbWritten != sizeof(INJECT_REMOTE_DATA)) goto err_write_data;

	IPCLOGV(L"CreateProcessW: Before CreateRemoteThread. " WPRDW, 0);

	if (!ReadProcessMemory(hProcess, pTargetData, pRemoteData, sizeof(INJECT_REMOTE_DATA), &cbRead) || cbRead != sizeof(INJECT_REMOTE_DATA)) goto err_read_data_0;

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
	FillMemory(pRemoteData, sizeof(INJECT_REMOTE_DATA), 0xFF);
	if (!ReadProcessMemory(hProcess, pTargetData, pRemoteData, sizeof(INJECT_REMOTE_DATA), &cbRead) || cbRead != sizeof(INJECT_REMOTE_DATA)) goto err_read_data;

	if (pRemoteData->uEverExecuted != 1) {
		IPCLOGE(L"Error: Remote thread never executed! (%u)", pRemoteData->uEverExecuted);
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
	IPCLOGE(L"ReadProcessMemory() Failed to read data: %ls", FormatErrorToStr(dwErrorCode));
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
	INJECT_REMOTE_DATA remoteData;
	DWORD dwReturn;

	IPCLOGV(L"CreateProcessW: Entering InjectTargetProcess. %llu", sizeof(remoteData));

	hProcess = pPi->hProcess;
	IPCLOGV(L"CreateProcessW: Before CopyMemory. " WPRDW, 0);

	CopyMemory(&remoteData.pxchConfig, g_pPxchConfig, sizeof(PROXYCHAINS_CONFIG));

	IPCLOGV(L"CreateProcessW: After CopyMemory. " WPRDW, 0);

	remoteData.dwErrorCode = -1;
	remoteData.dwParentPid = GetCurrentProcessId();
	remoteData.fpFreeLibrary = FreeLibrary;
	remoteData.fpGetModuleHandleW = GetModuleHandleW;
	remoteData.fpGetProcAddress = GetProcAddress;
	remoteData.fpLoadLibraryW = LoadLibraryW;
	remoteData.fpGetLastError = GetLastError;
	remoteData.fpOutputDebugStringA = OutputDebugStringA;
	remoteData.pSavedPxchConfig = NULL;
	remoteData.pSavedRemoteData = NULL;
	remoteData.dwDebugDepth = g_pRemoteData ? g_pRemoteData->dwDebugDepth + 1 : 1;

	IPCLOGV(L"CreateProcessW: After remoteData assignment. " WPRDW, 0);

	StringCchCopyA(remoteData.szInitFuncName, _countof(remoteData.szInitFuncName), g_pRemoteData ? g_pRemoteData->szInitFuncName : "InitHook");
	StringCchCopyA(remoteData.szCIWCVarName, _countof(remoteData.szCIWCVarName), g_pRemoteData ? g_pRemoteData->szCIWCVarName : "g_bCurrentlyInWinapiCall");
	CopyMemory(remoteData.chDebugOutput, g_pRemoteData ? g_pRemoteData->chDebugOutput : "A\0B\0C\0D\0E\0F\0G\0H\0I\0J\0K\0L\0M\0N\0O\0P\0Q\0R\0S\0T\0", sizeof(remoteData.chDebugOutput));
	StringCchCopyW(remoteData.szCygwin1ModuleName, _countof(remoteData.szCygwin1ModuleName), g_pRemoteData ? g_pRemoteData->szCygwin1ModuleName : L"cygwin1.dll");
	StringCchCopyW(remoteData.szCygwin1ModuleName, _countof(remoteData.szCygwin1ModuleName), g_pRemoteData ? g_pRemoteData->szHookDllModuleName : g_szHookDllFileName);
	remoteData.uEverExecuted = 0;
	remoteData.uStructSize = sizeof(INJECT_REMOTE_DATA);

	IPCLOGV(L"CreateProcessW: After StringCchCopy. " WPRDW, 0);

	dwReturn = RemoteCopyExecute(hProcess, &remoteData);

	if (dwReturn != 0) {
		return dwReturn;
	}
	IPCLOGV(L"CreateProcessW: After RemoteCopyExecute. " WPRDW, 0);

	if (remoteData.uEverExecuted == 0) {
		IPCLOGE(L"Error: Remote thread never executed!");
		//return ERROR_FUNCTION_NOT_CALLED;
	}

	if (remoteData.dwErrorCode != 0) {
		IPCLOGE(L"Error: Remote thread error: %ls!", FormatErrorToStr(remoteData.dwErrorCode));
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

	bRet = orig_fpCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, &processInformation);
	dwErrorCode = GetLastError();

	if (lpProcessInformation) {
		CopyMemory(lpProcessInformation, &processInformation, sizeof(PROCESS_INFORMATION));
	}

	LOGI(L"CreateProcessA: " WPRS L", " WPRS, lpApplicationName, lpCommandLine);

	if (!bRet) goto err_orig;

	dwReturn = InjectTargetProcess(&processInformation);
	if (!(dwCreationFlags & CREATE_SUSPENDED)) {
		ResumeThread(processInformation.hThread);
	}
	//if (GetCurrentProcessId() != g_pPxchConfig->dwMasterProcessId) IpcCommunicateWithServer();
	if (dwReturn != 0) goto err_inject;
	return 1;

err_orig:
	LOGE(L"CreateProcessA Error: " WPRDW L", %ls", bRet, FormatErrorToStr(dwErrorCode));
	SetLastError(dwErrorCode);
	return bRet;

err_inject:
	// PrintErrorToFile(stderr, dwReturn);
	SetLastError(dwReturn);
	return 1;
}

PROXY_FUNC(CreateProcessW)
{
	BOOL bRet;
	DWORD dwErrorCode;
	DWORD dwReturn = 0;
	PROCESS_INFORMATION processInformation;

	g_bCurrentlyInWinapiCall = TRUE;

	// For cygwin: cygwin fork() will duplicate the data in child process, including pointer g_*.
	IpcClientRestoreData();

	IPCLOGI(L"(In CreateProcessW) g_pRemoteData->dwDebugDepth = " WPRDW, g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);

	IPCLOGV(L"CreateProcessW: %ls, %ls, lpProcessAttributes: %#llx, lpThreadAttributes: %#llx, bInheritHandles: %d, dwCreationFlags: %#lx, lpCurrentDirectory: %s", lpApplicationName, lpCommandLine, (UINT64)lpProcessAttributes, (UINT64)lpThreadAttributes, bInheritHandles, dwCreationFlags, lpCurrentDirectory);

	bRet = orig_fpCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, &processInformation);
	dwErrorCode = GetLastError();

	IPCLOGV(L"CreateProcessW: Created.(%u) Child process id: " WPRDW, bRet, processInformation.dwProcessId);

	if (lpProcessInformation) {
		CopyMemory(lpProcessInformation, &processInformation, sizeof(PROCESS_INFORMATION));
	}

	IPCLOGV(L"CreateProcessW: Copied.");
	if (!bRet) goto err_orig;
	
	IPCLOGV(L"CreateProcessW: After jmp to err_orig.");
	IPCLOGV(L"CreateProcessW: Before InjectTargetProcess.");
	dwReturn = InjectTargetProcess(&processInformation);

	IPCLOGV(L"CreateProcessW: Injected. " WPRDW, dwReturn);

	if (!(dwCreationFlags & CREATE_SUSPENDED)) {
		ResumeThread(processInformation.hThread);
	}

	if (dwReturn != 0) goto err_inject;
	IPCLOGD(L"I've Injected WINPID " WPRDW, processInformation.dwProcessId);

	g_bCurrentlyInWinapiCall = FALSE;
	return 1;

err_orig:
	IPCLOGE(L"CreateProcessW Error: " WPRDW L", %ls", bRet, FormatErrorToStr(dwErrorCode));
	SetLastError(dwErrorCode);
	g_bCurrentlyInWinapiCall = FALSE;
	return bRet;

err_inject:
	IPCLOGE(L"Injecting WINPID " WPRDW L" Error: %ls", processInformation.dwProcessId, FormatErrorToStr(dwReturn));
	SetLastError(dwReturn);
	g_bCurrentlyInWinapiCall = FALSE;
	return 1;
}

PROXY_FUNC(CreateProcessAsUserW)
{
	BOOL bRet;
	DWORD dwErrorCode;
	DWORD dwReturn = 0;
	PROCESS_INFORMATION processInformation;

	g_bCurrentlyInWinapiCall = TRUE;

	// For cygwin: cygwin fork() will duplicate the data in child process, including pointer g_*.
	IpcClientRestoreData();

	IPCLOGI(L"(In CreateProcessAsUserW) g_pRemoteData->dwDebugDepth = " WPRDW, g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);

	IPCLOGV(L"CreateProcessAsUserW: %ls, %ls, lpProcessAttributes: %#llx, lpThreadAttributes: %#llx, bInheritHandles: %d, dwCreationFlags: %#lx, lpCurrentDirectory: %s", lpApplicationName, lpCommandLine, (UINT64)lpProcessAttributes, (UINT64)lpThreadAttributes, bInheritHandles, dwCreationFlags, lpCurrentDirectory);

	bRet = orig_fpCreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, &processInformation);
	dwErrorCode = GetLastError();

	IPCLOGV(L"CreateProcessAsUserW: Created.(%u) Child process id: " WPRDW, bRet, processInformation.dwProcessId);

	if (lpProcessInformation) {
		CopyMemory(lpProcessInformation, &processInformation, sizeof(PROCESS_INFORMATION));
	}

	IPCLOGV(L"CreateProcessAsUserW: Copied.");
	if (!bRet) goto err_orig;

	IPCLOGV(L"CreateProcessAsUserW: After jmp to err_orig.");
	IPCLOGV(L"CreateProcessAsUserW: Before InjectTargetProcess.");
	dwReturn = InjectTargetProcess(&processInformation);

	IPCLOGV(L"CreateProcessAsUserW: Injected. " WPRDW, dwReturn);

	if (!(dwCreationFlags & CREATE_SUSPENDED)) {
		ResumeThread(processInformation.hThread);
	}

	if (dwReturn != 0) goto err_inject;
	IPCLOGD(L"CreateProcessAsUserW: I've Injected WINPID " WPRDW, processInformation.dwProcessId);

	g_bCurrentlyInWinapiCall = FALSE;
	return 1;

err_orig:
	IPCLOGE(L"CreateProcessAsUserW Error: " WPRDW L", %ls", bRet, FormatErrorToStr(dwErrorCode));
	SetLastError(dwErrorCode);
	g_bCurrentlyInWinapiCall = FALSE;
	return bRet;

err_inject:
	IPCLOGE(L"Injecting WINPID " WPRDW L" Error: %ls", processInformation.dwProcessId, FormatErrorToStr(dwReturn));
	SetLastError(dwReturn);
	g_bCurrentlyInWinapiCall = FALSE;
	return 1;
}


PXCHDLL_API DWORD __stdcall InitHookForMain(PROXYCHAINS_CONFIG* pPxchConfig)
{
	g_pPxchConfig = pPxchConfig;

	MH_Initialize();
	// CREATE_HOOK(CreateProcessA);
	CREATE_HOOK(CreateProcessW);
	CREATE_HOOK(CreateProcessAsUserW);
	MH_EnableHook(MH_ALL_HOOKS);

	LOGI(L"Main Program Hooked!");
	return 0;
}

PXCHDLL_API DWORD __stdcall InitHook(INJECT_REMOTE_DATA* pRemoteData)
{
	DWORD dwErrorCode = 0;

	g_pPxchConfig = &pRemoteData->pxchConfig;
	g_pRemoteData = pRemoteData;

	DBGCHR('A');

	MH_Initialize();
	// CREATE_HOOK(CreateProcessA);
	CREATE_HOOK(CreateProcessW);
	CREATE_HOOK(CreateProcessAsUserW);

	DBGCHR('B');

	DBGCHR(g_pRemoteData->dwDebugDepth == 1 ? 'J' : 'K');
	IPCLOGI(L"(In InitHook) g_pRemoteData->dwDebugDepth = " WPRDW, g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);

	DBGCHR('C');

	if (1) do {
		HMODULE hWs2_32;
		HMODULE hWsock32;
		HMODULE hCygwin1;
		LPVOID pWs2_32_connect = NULL;
		LPVOID pWsock32_connect = NULL;
		LPVOID pCygwin1_connect = NULL;

		LoadLibraryW(L"ws2_32.dll");
		LoadLibraryW(L"wsock32.dll");
		LoadLibraryW(L"cygwin1.dll");

		if ((hWs2_32 = pRemoteData->fpGetModuleHandleW(L"ws2_32.dll"))) { pWs2_32_connect = pRemoteData->fpGetProcAddress(hWs2_32, "connect"); }
		if ((hWsock32 = pRemoteData->fpGetModuleHandleW(L"wsock32.dll"))) { pWsock32_connect = pRemoteData->fpGetProcAddress(hWsock32, "connect"); }
		if ((hCygwin1 = pRemoteData->fpGetModuleHandleW(L"cygwin1.dll"))) { pCygwin1_connect = pRemoteData->fpGetProcAddress(hCygwin1, "connect"); }

		IPCLOGI(L"ws2_32.dll  connect(): %p", pWs2_32_connect);
		IPCLOGI(L"wsock32.dll connect(): %p", pWsock32_connect);
		// IPCLOGI(L"mswsock.dll connect(): %p", hMswsock ? pRemoteData->fpGetProcAddress(hMswsock, "connect") : NULL);
		IPCLOGI(L"cygwin1.dll connect(): %p", pCygwin1_connect);

		CREATE_HOOK3_IFNOTNULL(Ws2_32, connect, pWs2_32_connect);
		CREATE_HOOK3_IFNOTNULL(Cygwin1, connect, pCygwin1_connect);
	} while (0);

	DBGCHR('D');

	if (g_pRemoteData->dwDebugDepth >= 0) {
		MH_EnableHook(MH_ALL_HOOKS);
	}
	else {
		IPCLOGI(L"(In InitHook) g_pRemoteData->dwDebugDepth = " WPRDW L", skipping MH_EnableHook", g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);
	}
	
	DBGCHR('E');
	// For non-direct descandant
	dwErrorCode = IpcClientRegisterChildProcess();
	if (dwErrorCode) {
		char tmpLogLine[100];
		StringCchPrintfA(tmpLogLine, 100, "IPC Error: %u", dwErrorCode);
		pRemoteData->fpOutputDebugStringA(tmpLogLine);
	}

	// For direct child
	pRemoteData->pSavedPxchConfig = g_pPxchConfig;
	pRemoteData->pSavedRemoteData = g_pRemoteData;
	DBGCHR('F');
	IPCLOGI(L"I'm WINPID " WPRDW L" Hooked!", log_pid);
	DBGCHR('G');
	return 0;
}

PXCHDLL_API void UninitHook(void)
{
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();

	IPCLOGI(L"I'm WINPID " WPRDW L" UnHooked!", log_pid);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		;
	}

	return TRUE;
}