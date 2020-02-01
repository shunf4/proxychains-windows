#include "stdafx.h"
#include <Shlwapi.h>
#ifdef __CYGWIN__
#include <strsafe.h>
#endif
#include <locale.h>
#include <ShellAPI.h>
#include <Sddl.h>

#include "pxch_defines.h"
#include "pxch_hook.h"
#include "common.h"
#include "log.h"
#include "ipc.h"

#ifndef __CYGWIN__
#pragma comment(lib, "Shlwapi.lib")
#endif

#ifdef __CYGWIN__
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <spawn.h>
#endif

typedef int IP_ADDRESS;

typedef DWORD pid_key_t;
typedef struct _ip_dl_element_t {
	IP_ADDRESS ip;
	struct _ip_dl_element_t* prev;
	struct _ip_dl_element_t* next;
} ip_dl_element_t;

typedef struct {
	REPORTED_CHILD_DATA data;
	ip_dl_element_t* fakeIps;

	UT_hash_handle hh;
} tab_per_process_t;

static tab_per_process_t* g_tabPerProcess;
HANDLE g_hDataMutex;

typedef struct {
	IP_ADDRESS ip;	// Key
	WCHAR szHostname[MAX_HOSTNAME_BUFSIZE];

	UT_hash_handle hh;
} tab_fake_ip_hostname_t;

static tab_fake_ip_hostname_t* g_tabFakeIpHostname;


typedef struct _IPC_INSTANCE {
	OVERLAPPED oOverlap;
	HANDLE hPipe;

	IPC_MSGBUF chReadBuf;
	DWORD cbRead;

	IPC_MSGBUF chWriteBuf;
	DWORD cbToWrite;

	DWORD dwState;

	BOOL bPending;

} IPC_INSTANCE;

#define LOCKED(proc) do { \
	DWORD dwWaitResult; \
	DWORD dwErrorCode; \
	DWORD dwReturn = 0; \
	 \
	dwWaitResult = WaitForSingleObject(g_hDataMutex, INFINITE); \
	switch (dwWaitResult) \
	{ \
	case WAIT_OBJECT_0: \
	{ \
		LOGV(L"Mutex fetched."); \
		proc \
	after_proc: \
		if (!ReleaseMutex(g_hDataMutex)) { \
			dwErrorCode = GetLastError(); \
			LOGC(L"Release mutex error: %ls", FormatErrorToStr(dwErrorCode)); \
			exit(dwErrorCode); \
		} \
		return dwReturn; \
	} \
	 \
	case WAIT_ABANDONED: \
		LOGC(L"Mutex abandoned!"); \
		exit(ERROR_ABANDONED_WAIT_0); \
		break; \
	 \
	default: \
		dwErrorCode = GetLastError(); \
		LOGW(L"Wait for mutex error: " WPRDW L", %ls", dwWaitResult, FormatErrorToStr(dwErrorCode)); \
		return dwErrorCode; \
	} \
} while(0)


DWORD ChildProcessExitedCallbackWorker(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
	LOCKED({
		tab_per_process_t * entry = (tab_per_process_t*)lpParameter;
		HASH_DELETE(hh, g_tabPerProcess, entry);
		LOGI(L"Child process pid " WPRDW L" exited.", entry->data.dwPid);
		HeapFree(GetProcessHeap(), 0, entry);

		if (g_tabPerProcess == NULL) {
			LOGI(L"All windows descendant process exited.");
			IF_WIN32_EXIT(0);
		}

		goto after_proc;
	});
}


VOID CALLBACK ChildProcessExitedCallback(
	_In_ PVOID   lpParameter,
	_In_ BOOLEAN TimerOrWaitFired
)
{
	ChildProcessExitedCallbackWorker(lpParameter, TimerOrWaitFired);
}

DWORD RegisterNewChildProcess(const REPORTED_CHILD_DATA* pChildData)
{
	LOCKED({
		tab_per_process_t* entry;
		HANDLE hWaitHandle;
		HANDLE hChildHandle;

		LOGV(L"Before HeapAlloc...");
		entry = (tab_per_process_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(tab_per_process_t));
		LOGV(L"After HeapAlloc...");
		if ((hChildHandle = OpenProcess(SYNCHRONIZE, FALSE, pChildData->dwPid)) == NULL) {
			dwReturn = GetLastError();
			LOGC(L"OpenProcess() error: %ls", FormatErrorToStr(dwReturn));
			goto after_proc;
		}
		LOGV(L"After OpenProcess...");

		if (!RegisterWaitForSingleObject(&hWaitHandle, hChildHandle, &ChildProcessExitedCallback, entry, INFINITE, WT_EXECUTELONGFUNCTION | WT_EXECUTEONLYONCE)) {
			dwReturn = GetLastError();
			LOGC(L"RegisterWaitForSingleObject() error: %ls", FormatErrorToStr(dwReturn));
			goto after_proc;
		}
		LOGV(L"After RegisterWaitForSingleObject...");
		entry->data = *pChildData;
		LOGV(L"After entry->data = *pChildData;");
		HASH_ADD(hh, g_tabPerProcess, data, sizeof(pid_key_t), entry);
		LOGV(L"After HASH_ADD");
		LOGI(L"Registered child pid " WPRDW, pChildData->dwPid);
	});
}

DWORD QueryChildStorage(REPORTED_CHILD_DATA* pChildData)
{
	LOCKED({
		tab_per_process_t* entry;
		HASH_FIND(hh, g_tabPerProcess, &pChildData->dwPid, sizeof(pid_key_t), entry);
		if (entry) {
			*pChildData = entry->data;
		}

		goto after_proc;
	});
}

DWORD HandleMessage(int i, IPC_INSTANCE* pipc)
{
	IPC_MSGBUF* pMsg = (IPC_MSGBUF*)pipc->chReadBuf;
	OutputDebugStringA("s:start handlemessage");

	if (MsgIsType(WSTR, pMsg)) {
		OutputDebugStringA("s:message is wstr");
		WCHAR sz[IPC_BUFSIZE / sizeof(WCHAR)];
		MessageToWstr(sz, *pMsg, pipc->cbRead);
		StdWprintf(STD_ERROR_HANDLE, L"%ls", sz);
		StdFlush(STD_ERROR_HANDLE);

		goto after_handling_resp_ok;
	}

	if (MsgIsType(CHILDDATA, pMsg)) {
		OutputDebugStringA("s:message is childdata");
		REPORTED_CHILD_DATA childData;
		// LOGV(L"Message is CHILDDATA");
		MessageToChildData(&childData, *pMsg, pipc->cbRead);
		// LOGD(L"Child process pid " WPRDW L" created.", childData.dwPid);
		// LOGV(L"RegisterNewChildProcess...");
		RegisterNewChildProcess(&childData);
		// LOGV(L"RegisterNewChildProcess done.");
		goto after_handling_resp_ok;
	}

	if (MsgIsType(QUERYSTORAGE, pMsg)) {
		OutputDebugStringA("s:message is querystorage");
		REPORTED_CHILD_DATA childData = { 0 };
		// LOGV(L"Message is QUERYSTORAGE");
		MessageToQueryStorage(&childData.dwPid, *pMsg, pipc->cbRead);
		QueryChildStorage(&childData);
		ChildDataToMessage(pipc->chWriteBuf, &pipc->cbToWrite, &childData);
		goto ret;
	}

	goto after_handling_not_recognized;

after_handling_resp_ok:
	WstrToMessage(pipc->chWriteBuf, &pipc->cbToWrite, L"OK");
	return 0;

after_handling_not_recognized:
	WstrToMessage(pipc->chWriteBuf, &pipc->cbToWrite, L"NOT RECOGNIZED");
	return 0;

ret:
	return 0;
}

DWORD ConnectToNewClient(HANDLE hPipe, LPOVERLAPPED lpo)
{
	BOOL bConnected;
	DWORD dwErrorCode;

	bConnected = ConnectNamedPipe(hPipe, lpo);
	dwErrorCode = GetLastError();

	// Should return zero because it's overlapped
	if (bConnected != 0) goto err_connected_not_zero;


	switch (dwErrorCode) {
	case ERROR_IO_PENDING:
		return ERROR_IO_PENDING;

	case ERROR_PIPE_CONNECTED:
		if (!SetEvent(lpo->hEvent)) goto err_set_event;
		return ERROR_PIPE_CONNECTED;

	default:
		goto err_other_codes;
	}

err_set_event:
	LOGE(L"Error signaling event: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;

err_other_codes:
err_connected_not_zero:
	LOGE(L"Error connecting pipe: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;
}

DWORD DisconnectAndReconnect(IPC_INSTANCE* ipc, int i)
{
	DWORD dwErrorCode;

	if (!DisconnectNamedPipe(ipc[i].hPipe)) {
		LOGE(L"[IPC%03d] disconnect failed: %ls.", i, FormatErrorToStr(GetLastError()));
	}

	dwErrorCode = ConnectToNewClient(ipc[i].hPipe, &ipc[i].oOverlap);
	if (dwErrorCode != ERROR_IO_PENDING && dwErrorCode != ERROR_PIPE_CONNECTED) return dwErrorCode;

	ipc[i].bPending = (dwErrorCode == ERROR_IO_PENDING);
	ipc[i].dwState = (dwErrorCode == ERROR_PIPE_CONNECTED) ? IPC_STATE_READING : IPC_STATE_CONNECTING;
	return 0;
}

DWORD WINAPI ServerLoop(LPVOID lpVoid)
{
	static IPC_INSTANCE ipc[IPC_INSTANCE_NUM];
	static HANDLE hEvents[IPC_INSTANCE_NUM];
	PROXYCHAINS_CONFIG* pPxchConfig = (PROXYCHAINS_CONFIG*)lpVoid;
	DWORD dwErrorCode;
	DWORD dwWait;
	DWORD cbReturn;
	BOOL bReturn;
	int i;
	SECURITY_ATTRIBUTES SecAttr;
	PSECURITY_DESCRIPTOR pSecDesc;

	// https://docs.microsoft.com/zh-cn/windows/win32/secauthz/security-descriptor-string-format
	// https://stackoverflow.com/questions/9589141/low-integrity-to-medium-high-integrity-pipe-security-descriptor
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;0x12019f;;;WD)S:(ML;;NW;;;LW)", SDDL_REVISION_1, &pSecDesc, NULL)) return GetLastError();

	SecAttr.nLength = sizeof(SecAttr);
	SecAttr.bInheritHandle = FALSE;
	SecAttr.lpSecurityDescriptor = pSecDesc;

	// Initialize
	for (i = 0; i < IPC_INSTANCE_NUM; i++) {
		// Manual-reset, initially signaled event
		hEvents[i] = CreateEventW(NULL, TRUE, TRUE, NULL);
		if (hEvents[i] == 0) goto err_create_event;

		ipc[i].oOverlap.hEvent = hEvents[i];

		ipc[i].hPipe = CreateNamedPipeW(pPxchConfig->szIpcPipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, IPC_INSTANCE_NUM, IPC_BUFSIZE, IPC_BUFSIZE, 0, &SecAttr);

		if (ipc[i].hPipe == INVALID_HANDLE_VALUE) goto err_create_pipe;

		dwErrorCode = ConnectToNewClient(ipc[i].hPipe, &ipc[i].oOverlap);
		if (dwErrorCode != ERROR_IO_PENDING && dwErrorCode != ERROR_PIPE_CONNECTED) return dwErrorCode;

		ipc[i].bPending = (dwErrorCode == ERROR_IO_PENDING);

		ipc[i].dwState = (dwErrorCode == ERROR_PIPE_CONNECTED) ? IPC_STATE_READING : IPC_STATE_CONNECTING;
	}

	LOGD(L"[IPCALL] Waiting for clients...");
	LOGV(L"ServerLoop: Signaling semaphore...");
	if (!ReleaseSemaphore(g_hIpcServerSemaphore, 1, NULL)) {
		dwErrorCode = GetLastError();
		LOGC(L"Release semaphore error: %ls", FormatErrorToStr(dwErrorCode));
		exit(dwErrorCode);
	}
	// CloseHandle(g_hIpcServerSemaphore);
	OutputDebugStringA("s:signal1");
	// LOGV(L"ServerLoop: Signaled semaphore.");
	OutputDebugStringA("s:signal");

	while (1) {
		OutputDebugStringA("s:before wait");
#ifndef __CYGWIN__
		dwWait = WaitForMultipleObjects(IPC_INSTANCE_NUM, hEvents, FALSE, INFINITE);
#else
		dwWait = WaitForMultipleObjects(IPC_INSTANCE_NUM, hEvents, FALSE, 100);
		if (dwWait == WAIT_TIMEOUT) {
			BOOL bChild = FALSE;
			int iChildPid = 0;
			while ((iChildPid = waitpid((pid_t)(-1), 0, WNOHANG)) > 0) { bChild = TRUE; }
			if (bChild) {
				// LOGI(L"Cygwin child process exited (between WaitForMultipleObjects()).");
				IF_CYGWIN_EXIT(0);
			}
			continue;
		}
#endif
		OutputDebugStringA("s:after wait");
		i = dwWait - WAIT_OBJECT_0;
		if (i < 0 || i >= IPC_INSTANCE_NUM) goto err_wait_out_of_range;

		// If this pipe is just awaken from pending state
		if (ipc[i].bPending) {
			OutputDebugStringA("s:before GetOverlappedResult");
			bReturn = GetOverlappedResult(ipc[i].hPipe, &ipc[i].oOverlap, &cbReturn, FALSE);
			OutputDebugStringA("s:after GetOverlappedResult");

			switch (ipc[i].dwState) {
			case IPC_STATE_CONNECTING:
				if (!bReturn) goto err_connect_overlapped_error;
				OutputDebugStringA("s:connected");
				// LOGV(L"[IPC%03d] named pipe connected.", i);
				ipc[i].dwState = IPC_STATE_READING;
				OutputDebugStringA("s:after set dwState");
				break;

			case IPC_STATE_READING:
				if (!bReturn || cbReturn == 0) {
					dwErrorCode = GetLastError();
					if (dwErrorCode != ERROR_BROKEN_PIPE) {
						// LOGE(L"[IPC%03d] GetOverlappedResult() error(" WPRDW L") or read 0 bytes(" WPRDW L"), disconnect and reconnecting", i, dwErrorCode, cbReturn);
					}
					if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
					continue;
				}
				// LOGV(L"[IPC%03d] ReadFile() received msglen = " WPRDW L"", i, cbReturn);
				ipc[i].cbRead = cbReturn;
				ipc[i].dwState = IPC_STATE_WRITING;
				break;

			case IPC_STATE_WRITING:
				if (!bReturn || cbReturn != ipc[i].cbToWrite) {
					dwErrorCode = GetLastError();
					if (dwErrorCode != ERROR_BROKEN_PIPE) {
						// LOGE(L"[IPC%03d] GetOverlappedResult() error(" WPRDW L") or wrote " WPRDW L" bytes (!= " WPRDW L" as expected), disconnect and reconnecting", i, dwErrorCode, cbReturn, ipc[i].cbToWrite);
					}
					if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
					continue;
				}
				// LOGV(L"[IPC%03d] WriteFile() sent msglen = " WPRDW L"", i, cbReturn);
				ipc[i].dwState = IPC_STATE_READING;
				break;

			default:
				// LOGE(L"[IPC%03d] Invalid pipe state: " WPRDW L"", i, ipc[i].dwState);
				return ERROR_INVALID_STATE;
			}
		}

		// Last operation has finished, now dwState stores what to do next
		switch (ipc[i].dwState) {
		case IPC_STATE_READING:
			OutputDebugStringA("s:before ReadFile");
			bReturn = ReadFile(ipc[i].hPipe, ipc[i].chReadBuf, IPC_BUFSIZE, &ipc[i].cbRead, &ipc[i].oOverlap);
			OutputDebugStringA("s:after ReadFile");

			// Finished instantly
			if (bReturn && ipc[i].cbRead != 0) {
				// LOGV(L"[IPC%03d] ReadFile() received msglen = " WPRDW L" (immediately)", i, ipc[i].cbRead);
				ipc[i].bPending = FALSE;
				ipc[i].dwState = IPC_STATE_WRITING;
				continue;
			}

			// Pending
			dwErrorCode = GetLastError();
			if (!bReturn && (dwErrorCode == ERROR_IO_PENDING)) {
				ipc[i].bPending = TRUE;
				continue;
			}

			if (dwErrorCode != ERROR_BROKEN_PIPE) {
				// LOGE(L"[IPC%03d] ReadFile() error: %ls or has read 0 bytes; disconnecting and reconnecting", i, FormatErrorToStr(dwErrorCode));
			}
			if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
			break;

		case IPC_STATE_WRITING:
			OutputDebugStringA("s:before handlemessage");
			dwErrorCode = HandleMessage(i, &ipc[i]);
			OutputDebugStringA("s:after handlemessage");
			// LOGV(L"HandleMessage done.");

			if (dwErrorCode != NO_ERROR) {
				// LOGE(L"[IPC%03d] Handle message error: %ls; disconnecting and reconnecting", i, FormatErrorToStr(dwErrorCode));
				if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
				break;
			}

			// LOGV(L"[IPC%03d] Writing pipe...", i);
			bReturn = WriteFile(ipc[i].hPipe, ipc[i].chWriteBuf, ipc[i].cbToWrite, &cbReturn, &ipc[i].oOverlap);
			// LOGV(L"[IPC%03d] Written pipe.", i);

			// Finished instantly
			if (bReturn && cbReturn == ipc[i].cbToWrite) {
				// LOGV(L"[IPC%03d] WriteFile() sent msglen = " WPRDW L" (immediately)", i, cbReturn);
				ipc[i].bPending = FALSE;
				ipc[i].dwState = IPC_STATE_READING;
				continue;
			}

			// Pending
			dwErrorCode = GetLastError();
			if (!bReturn && (dwErrorCode == ERROR_IO_PENDING)) {
				ipc[i].bPending = TRUE;
				continue;
			}

			if (dwErrorCode != ERROR_BROKEN_PIPE) {
				// LOGE(L"[IPC%03d] Write() error: %ls or wrote unexpected bytes(" WPRDW L", different from " WPRDW L" as expected); disconnecting and reconnecting", i, FormatErrorToStr(dwErrorCode), cbReturn, ipc[i].cbToWrite);
			}
			if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
			break;

		default:
			// LOGE(L"[IPC%03d] Invalid pipe state: " WPRDW L"", i, ipc[i].dwState);
			return ERROR_INVALID_STATE;
		}
	}
	return 0;

err_create_event:
	dwErrorCode = GetLastError();
	LOGE(L"Error creating event: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;

err_create_pipe:
	dwErrorCode = GetLastError();
	LOGE(L"Error creating pipe: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;

err_wait_out_of_range:
	dwErrorCode = GetLastError();
	LOGE(L"WaitForMultipleObjects() out of range: %d, last error: %ls", i, FormatErrorToStr(dwErrorCode));
	return ERROR_DS_RANGE_CONSTRAINT;

err_connect_overlapped_error:
	dwErrorCode = GetLastError();
	LOGE(L"[IPC%03d] GetOverlappedResult() error: %ls", i, FormatErrorToStr(dwErrorCode));
	return dwErrorCode;

}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
		wprintf(L"[PX:Ctrl-C]");
		Beep(750, 300);
		return TRUE;

		// CTRL-CLOSE: confirm that the user wants to exit. 
	case CTRL_CLOSE_EVENT:
		Beep(600, 200);
		wprintf(L"Ctrl-Close event");
		return TRUE;

		// Pass other signals to the next handler. 
	case CTRL_BREAK_EVENT:
		Beep(900, 200);
		wprintf(L"Ctrl-Break event");
		return FALSE;

	case CTRL_LOGOFF_EVENT:
		Beep(1000, 200);
		wprintf(L"Ctrl-Logoff event");
		return FALSE;

	case CTRL_SHUTDOWN_EVENT:
		Beep(750, 500);
		wprintf(L"Ctrl-Shutdown event");
		return FALSE;

	default:
		return FALSE;
	}
}

DWORD LoadConfiguration(PROXYCHAINS_CONFIG* pPxchConfig)
{
	DWORD dwRet;
	FILETIME ft;
	ULARGE_INTEGER uli;
	//SIZE_T dirLength = 0;

	pPxchConfig->dwMasterProcessId = GetCurrentProcessId();
	GetSystemTimeAsFileTime(&ft);
	uli.HighPart = ft.dwHighDateTime;
	uli.LowPart = ft.dwLowDateTime;
	StringCchPrintfW(pPxchConfig->szIpcPipeName, _countof(pPxchConfig->szIpcPipeName), L"\\\\.\\pipe\\proxychains_" WPRDW L"_%" PREFIX_L(PRIu64) L"", GetCurrentProcessId(), uli.QuadPart);
	pPxchConfig->testNum = 1234;

	dwRet = GetModuleFileNameW(NULL, pPxchConfig->szHookDllPath, MAX_DLL_PATH_BUFSIZE);
	if (dwRet == 0) goto err_insuf_buf;
	if (dwRet == MAX_DLL_PATH_BUFSIZE) goto err_insuf_buf;

	if (!PathRemoveFileSpecW(pPxchConfig->szHookDllPath)) goto err_insuf_buf;

	if (FAILED(StringCchCatW(pPxchConfig->szHookDllPath, MAX_DLL_PATH_BUFSIZE, L"\\"))) goto err_insuf_buf;
	if (FAILED(StringCchCopyW(pPxchConfig->szMinHookDllPath, MAX_DLL_PATH_BUFSIZE, pPxchConfig->szHookDllPath))) goto err_insuf_buf;
	if (FAILED(StringCchCatW(pPxchConfig->szHookDllPath, MAX_DLL_PATH_BUFSIZE, g_szHookDllFileName))) goto err_insuf_buf;
	if (FAILED(StringCchCatW(pPxchConfig->szMinHookDllPath, MAX_DLL_PATH_BUFSIZE, g_szMinHookDllFileName))) goto err_insuf_buf;

	if (!PathFileExistsW(pPxchConfig->szHookDllPath)) goto err_dll_not_exist;
	if (!PathFileExistsW(pPxchConfig->szMinHookDllPath)) pPxchConfig->szMinHookDllPath[0] = L'\0';

	return 0;

	//err_other:
	//	return GetLastError();
err_insuf_buf:
	return ERROR_INSUFFICIENT_BUFFER;

err_dll_not_exist:
	return ERROR_FILE_NOT_FOUND;
}

BOOL ArgHasSpecialChar(WCHAR* sz)
{
	WCHAR* p = sz;
	while (*p) {
		if (*p == L'\t') return TRUE;
		if (*p == L'\n') return TRUE;
		if (*p == L'\v') return TRUE;
		if (*p == L'\"') return TRUE;
		p++;
	}
	return FALSE;
}

DWORD ParseArgs(PROXYCHAINS_CONFIG* pConfig, int argc, WCHAR* argv[], int* piCommandStart)
{
	int i;
	int iCountCommands = 0;
	BOOL bOptionFile = FALSE;
	int iOptionPrefixLen;
	BOOL bOptionHasValue;
	BOOL bOptionsEnd = FALSE;
	BOOL bForceQuote = FALSE;
	DWORD dwErrorCode;
	WCHAR* pWchar;
	WCHAR* pCommandLine;

	pConfig->szConfigPath[0] = L'\0';
	pConfig->szCommandLine[0] = L'\0';
	pCommandLine = pConfig->szCommandLine;

	for (i = 1; i < argc; i++) {
		pWchar = argv[i];
		if (!bOptionsEnd) {

		option_value_following:
			if (bOptionFile) {
				if (FAILED(StringCchCopyW(pConfig->szConfigPath, _countof(pConfig->szConfigPath), pWchar))) goto err_insuf_buf;
				bOptionFile = FALSE;
				continue;
			}

			bOptionHasValue = FALSE;

			if (wcsncmp(pWchar, L"-f", 2) == 0) {
				bOptionFile = TRUE;
				iOptionPrefixLen = 2;
				bOptionHasValue = TRUE;
			}
			else if (wcsncmp(pWchar, L"-q", 2) == 0) {
				pConfig->bQuiet = TRUE;
				continue;
			}
			else {
				bOptionsEnd = TRUE;
				i--;
				continue;
			}

			if (bOptionHasValue) {
				if (wcslen(pWchar) > iOptionPrefixLen) {
					pWchar += 2;
					goto option_value_following;
				}
				else continue;
			}
		}
		// else
		// Option Ends, Command starts
#ifdef __CYGWIN__
		* piCommandStart = i;
		return 0;
#endif
		iCountCommands++;
		if (iCountCommands > 1) {
			if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
				goto err_insuf_buf;
			}
			*(pCommandLine++) = L' ';
		}
		else {
			WCHAR szExecPath[MAX_COMMAND_EXEC_PATH_BUFSIZE];
			if (SearchPath(NULL, pWchar, NULL, _countof(szExecPath), szExecPath, NULL) == 0) {
				if (SearchPath(NULL, pWchar, L".exe", _countof(szExecPath), szExecPath, NULL) == 0) {
					goto err_get_exec_path;
				}
			}
			pWchar = szExecPath;
		}

		if (!bForceQuote && *pWchar != L'\0' && !ArgHasSpecialChar(pWchar)) {
			if (FAILED(StringCchCopyEx(pCommandLine, _countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine), pWchar, &pCommandLine, NULL, 0))) goto err_insuf_buf;
		}
		else {
			if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
				goto err_insuf_buf;
			}
			*(pCommandLine++) = L'"';

			while (*pWchar) {
				UINT32 uCountBackslashes = 0;
				while (*pWchar && *pWchar == L'\\') {
					pWchar++;
					uCountBackslashes++;
				}
				if (*pWchar == L'\0') {
					UINT32 u;
					uCountBackslashes *= 2;
					for (u = 0; u < uCountBackslashes; u++) {
						if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
							goto err_insuf_buf;
						}
						*(pCommandLine++) = L'\\';
					}
				}
				else if (*pWchar == L'"') {
					UINT32 u;
					uCountBackslashes *= 2;
					uCountBackslashes += 1;
					for (u = 0; u < uCountBackslashes + 1; u++) {
						if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
							goto err_insuf_buf;
						}
						if (u != uCountBackslashes) {
							*(pCommandLine++) = L'\\';
						}
						else {
							*(pCommandLine++) = L'"';
						}
					}
				}
				else {
					UINT32 u;
					for (u = 0; u < uCountBackslashes + 1; u++) {
						if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
							goto err_insuf_buf;
						}
						if (u != uCountBackslashes) {
							*(pCommandLine++) = L'\\';
						}
						else {
							*(pCommandLine++) = *pWchar;
						}
					}
				}

				if (*pWchar == L'\0') {
					break;
				}
				pWchar++;
			}
			if (_countof(pConfig->szCommandLine) - (pCommandLine - pConfig->szCommandLine) - 1 < 1) {
				goto err_insuf_buf;
			}
			*(pCommandLine++) = L'"';
		}
	}
	*pCommandLine = L'\0';

	if (iCountCommands == 0) {
		return ERROR_INVALID_COMMAND_LINE;
	}

	return 0;

err_insuf_buf:
	LOGE(L"Error when parsing args: Insufficient Buffer");
	return ERROR_INSUFFICIENT_BUFFER;

err_get_exec_path:
	dwErrorCode = GetLastError();
	LOGE(L"Error when parsing args: SearchPath() Failed: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;
}

DWORD InitData(void)
{
	g_tabPerProcess = NULL;
	g_tabFakeIpHostname = NULL;

	if ((g_hDataMutex = CreateMutexW(NULL, FALSE, NULL)) == NULL) return GetLastError();
	if ((g_hIpcServerSemaphore = CreateSemaphoreW(NULL, 0, 1, NULL)) == NULL) return GetLastError();

	return 0;
}

#ifndef __CYGWIN__

int wmain(int argc, WCHAR* argv[])
{
	PROXYCHAINS_CONFIG config = { 0 };
	DWORD dwError;
	DWORD dwTid;
	STARTUPINFO startupInfo = { 0 };
	PROCESS_INFORMATION processInformation = { 0 };
	int iCommandStart;

	g_pPxchConfig = &config;

	setvbuf(stderr, NULL, _IOFBF, 65536);

	LOGI(L"Locale: %S", setlocale(LC_ALL, ""));
	SetConsoleCtrlHandler(CtrlHandler, TRUE);
	
	if ((dwError = InitData()) != NOERROR) goto err;
	if ((dwError = LoadConfiguration(&config)) != NOERROR) goto err;

	LOGI(L"DLL Path: %ls", config.szHookDllPath);
	LOGI(L"MinHook DLL Path: %ls", config.szMinHookDllPath);

	InitHookForMain(&config);

	if ((dwError = ParseArgs(g_pPxchConfig, argc, argv, &iCommandStart)) != NOERROR) goto err;

	LOGI(L"Config Path: %ls", config.szConfigPath);
	LOGI(L"Pipe name: %ls", config.szIpcPipeName);
	LOGI(L"Quiet: %ls", config.bQuiet ? L"Y" : L"N");
	LOGI(L"Command Line: %ls", config.szCommandLine);

	if (CreateThread(0, 0, &ServerLoop, g_pPxchConfig, 0, &dwTid) == NULL) goto err_get;
	LOGI(L"IPC Server Tid: " WPRDW, dwTid);

	if (g_hIpcServerSemaphore != NULL) {
		DWORD dwWaitResult;
		DWORD dwErrorCode;

		LOGV(L"Waiting for g_hIpcServerSemaphore.");

		dwWaitResult = WaitForSingleObject(g_hIpcServerSemaphore, INFINITE);
		switch (dwWaitResult)
		{
		case WAIT_OBJECT_0:
			if (!ReleaseSemaphore(g_hIpcServerSemaphore, 1, NULL)) {
				dwErrorCode = GetLastError();
				LOGC(L"Release semaphore error: %ls", FormatErrorToStr(dwErrorCode));
				exit(dwErrorCode);
			}
			CloseHandle(g_hIpcServerSemaphore);
			g_hIpcServerSemaphore = NULL;
			break;

		case WAIT_ABANDONED:
			LOGC(L"Mutex abandoned!");
			Sleep(INFINITE);
			exit(ERROR_ABANDONED_WAIT_0);
			break;

		default:
			dwErrorCode = GetLastError();
			LOGW(L"Wait for semaphore error: " WPRDW L", %ls", dwWaitResult, FormatErrorToStr(dwErrorCode));
			exit(dwErrorCode);
		}
	}

	if (!ProxyCreateProcessW(NULL, config.szCommandLine, 0, 0, 1, 0, 0, 0, &startupInfo, &processInformation)) goto err_get;
	Sleep(INFINITE);
	return 0;

err_get:
	dwError = GetLastError();
err:
	PrintErrorToFile(stderr, dwError);
	return dwError;
}

#else 

void handle_sigchld(int sig)
{
	while (waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
	LOGI(L"Cygwin child process exited.");

	IF_CYGWIN_EXIT(0);
}

void handle_sigint(int sig)
{
	// Once hooked, a cygwin program cannot handle Ctrl-C signal.
	// Thus we have to implement this to kill everything forked
	// by proxychains
	tab_per_process_t* current;
	tab_per_process_t* tmp;
	HANDLE h;

	LOGW(L"[PX:Ctrl-C]");
	fflush(stderr);
	HASH_ITER(hh, g_tabPerProcess, current, tmp) {
		HASH_DELETE(hh, g_tabPerProcess, current);
		h = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, current->data.dwPid);
		if ((h != NULL || h != INVALID_HANDLE_VALUE) && TerminateProcess(h, 0)) {
			LOGW(L"Killed WINPID " WPRDW, current->data.dwPid);
		}
		else {
			LOGW(L"Unable to kill WINPID " WPRDW, current->data.dwPid);
		}
		HeapFree(GetProcessHeap(), 0, current);
	}
	IF_CYGWIN_EXIT(0);
}

DWORD WINAPI CygwinSpawn(LPVOID lpParam)
{
	void** ctx = lpParam;
	pid_t child_pid;
	char*const* p_argv_command_start = ctx[0];
	char*const* envp = ctx[1];
	int iReturn;

	iReturn = posix_spawnp(&child_pid, *p_argv_command_start, NULL, NULL, p_argv_command_start, envp);
	LOGD(L"Spawn ret: %d; CYGPID: " WPRDW L"", iReturn, child_pid);

	return 0;
}

int main(int argc, char* const argv[], char* const envp[])
{
	PROXYCHAINS_CONFIG config = { 0 };
	DWORD dwError = 0;
	DWORD dwTid;
	int iCommandStart;
	int i;

	// char* spawn_argv[] = { "bash.exe", NULL };
	WCHAR** wargv = malloc(argc * sizeof(WCHAR*));
	const void* ctx[2];

	g_pPxchConfig = &config;
	setvbuf(stderr, NULL, _IOFBF, 65536);

	for (i = 0; i < argc; i++) {
		int iNeededChars = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
		wargv[i] = malloc(iNeededChars * sizeof(WCHAR));
		MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wargv[i], iNeededChars);
	}

	LOGI(L"Locale: %S", setlocale(LC_ALL, ""));

	if ((dwError = InitData()) != NOERROR) goto err;
	if ((dwError = LoadConfiguration(&config)) != NOERROR) goto err;

	LOGI(L"DLL Path: %ls", config.szHookDllPath);
	LOGI(L"MinHook DLL Path: %ls", config.szMinHookDllPath);

	InitHookForMain(&config);

	if ((dwError = ParseArgs(g_pPxchConfig, argc, wargv, &iCommandStart)) != NOERROR) goto err;

	LOGI(L"Config Path: %ls", config.szConfigPath);
	LOGI(L"Pipe name: %ls", config.szIpcPipeName);
	LOGI(L"Quiet: %ls", config.bQuiet ? L"Y" : L"N");
	LOGI(L"argv[iCommandStart]: %S", argv[iCommandStart]);

	if (CreateThread(0, 0, &ServerLoop, g_pPxchConfig, 0, &dwTid) == NULL) goto err_get;
	LOGI(L"IPC Server Tid: " WPRDW, dwTid);

	if (g_hIpcServerSemaphore != NULL) {
		DWORD dwWaitResult;
		DWORD dwErrorCode;

		LOGV(L"Waiting for g_hIpcServerSemaphore.");

		dwWaitResult = WaitForSingleObject(g_hIpcServerSemaphore, INFINITE);
		switch (dwWaitResult)
		{
		case WAIT_OBJECT_0:
			if (!ReleaseSemaphore(g_hIpcServerSemaphore, 1, NULL)) {
				dwErrorCode = GetLastError();
				LOGC(L"Release semaphore error: %ls", FormatErrorToStr(dwErrorCode));
				exit(dwErrorCode);
			}
			CloseHandle(g_hIpcServerSemaphore);
			g_hIpcServerSemaphore = NULL;
			break;

		case WAIT_ABANDONED:
			LOGC(L"Mutex abandoned!");
			Sleep(INFINITE);
			exit(ERROR_ABANDONED_WAIT_0);
			break;

		default:
			dwErrorCode = GetLastError();
			LOGW(L"Wait for semaphore error: " WPRDW L", %ls", dwWaitResult, FormatErrorToStr(dwErrorCode));
			exit(dwErrorCode);
		}
	}

	ctx[0] = &argv[iCommandStart];
	ctx[1] = envp;

	// if (CreateThread(0, 0, &CygwinSpawn, ctx, 0, &dwTid) == NULL) goto err_get;
	// LOGI(L"Cygwin spawn Tid: " WPRDW, dwTid);
	
	CygwinSpawn(ctx);
	// i = posix_spawnp(&child_pid, &argv[iCommandStart], NULL, NULL, p_argv_command_start, p_envp);
	// LOGD(L"Spawn ret: %d; CYGPID: " WPRDW L"", i, child_pid);

	signal(SIGINT, handle_sigint);
	signal(SIGCHLD, handle_sigchld);

	pause();

#ifdef __CYGWIN_PXCH_FORK__
	child_pid = fork();
	if (child_pid) {
		// Parent
		int status;
		LOGI(L"I'm parent");
		// waitpid(-1, &status, 0);
		signal(SIGCHLD, handle_sigchld);
		ServerLoop(g_pPxchConfig, INVALID_HANDLE_VALUE);
	}
	else {
		// Child
		LOGI(L"I'm child\n");
		execvp(argv[iCommandStart], &argv[iCommandStart]);
	}
#endif
	return 0;

err_get:
	dwError = GetLastError();
err:
	PrintErrorToFile(stderr, dwError);
	return dwError;
}
#endif