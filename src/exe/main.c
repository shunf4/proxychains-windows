#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#include "includes_win32.h"
#include <ShellAPI.h>
#include <Sddl.h>

#include <strsafe.h>

#include "log_win32.h"
#include "hookdll_win32.h"
#include "proc_bookkeeping_win32.h"

#ifdef __CYGWIN__
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <spawn.h>
#endif

HANDLE g_hIpcServerSemaphore;

DWORD HandleMessage(int i, IPC_INSTANCE* pipc);

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
	LOGV(L"ServerLoop: Signaled semaphore.");

	while (1) {
#ifndef __CYGWIN__
		dwWait = WaitForMultipleObjects(IPC_INSTANCE_NUM, hEvents, FALSE, INFINITE);
#else
		dwWait = WaitForMultipleObjects(IPC_INSTANCE_NUM, hEvents, FALSE, 100);
		if (dwWait == WAIT_TIMEOUT) {
			BOOL bChild = FALSE;
			int iChildPid = 0;
			while ((iChildPid = waitpid((pid_t)(-1), 0, WNOHANG)) > 0) { bChild = TRUE; }
			if (bChild) {
				LOGI(L"Cygwin child process exited (between WaitForMultipleObjects()). Master exiting");
				IF_CYGWIN_EXIT(0);
			}
			continue;
		}
#endif
		i = dwWait - WAIT_OBJECT_0;
		if (i < 0 || i >= IPC_INSTANCE_NUM) goto err_wait_out_of_range;

		// If this pipe is just awaken from pending state
		if (ipc[i].bPending) {
			bReturn = GetOverlappedResult(ipc[i].hPipe, &ipc[i].oOverlap, &cbReturn, FALSE);

			switch (ipc[i].dwState) {
			case IPC_STATE_CONNECTING:
				if (!bReturn) goto err_connect_overlapped_error;
				LOGV(L"[IPC%03d] named pipe connected.", i);
				ipc[i].dwState = IPC_STATE_READING;
				break;

			case IPC_STATE_READING:
				if (!bReturn || cbReturn == 0) {
					dwErrorCode = GetLastError();
					if (dwErrorCode != ERROR_BROKEN_PIPE) {
						LOGE(L"[IPC%03d] GetOverlappedResult() error(" WPRDW L") or read 0 bytes(" WPRDW L"), disconnect and reconnecting", i, dwErrorCode, cbReturn);
					}
					if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
					continue;
				}
				LOGV(L"[IPC%03d] ReadFile() received msglen = " WPRDW L"", i, cbReturn);
				ipc[i].cbRead = cbReturn;
				ipc[i].dwState = IPC_STATE_WRITING;
				break;

			case IPC_STATE_WRITING:
				if (!bReturn || cbReturn != ipc[i].cbToWrite) {
					dwErrorCode = GetLastError();
					if (dwErrorCode != ERROR_BROKEN_PIPE) {
						LOGE(L"[IPC%03d] GetOverlappedResult() error(" WPRDW L") or wrote " WPRDW L" bytes (!= " WPRDW L" as expected), disconnect and reconnecting", i, dwErrorCode, cbReturn, ipc[i].cbToWrite);
					}
					if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
					continue;
				}
				LOGV(L"[IPC%03d] WriteFile() sent msglen = " WPRDW L"", i, cbReturn);
				ipc[i].dwState = IPC_STATE_READING;
				break;

			default:
				LOGE(L"[IPC%03d] Invalid pipe state: " WPRDW L"", i, ipc[i].dwState);
				return ERROR_INVALID_STATE;
			}
		}

		// Last operation has finished, now dwState stores what to do next
		switch (ipc[i].dwState) {
		case IPC_STATE_READING:
			bReturn = ReadFile(ipc[i].hPipe, ipc[i].chReadBuf, IPC_BUFSIZE, &ipc[i].cbRead, &ipc[i].oOverlap);

			// Finished instantly
			if (bReturn && ipc[i].cbRead != 0) {
				LOGV(L"[IPC%03d] ReadFile() received msglen = " WPRDW L" (immediately)", i, ipc[i].cbRead);
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
				LOGE(L"[IPC%03d] ReadFile() error: %ls or has read 0 bytes; disconnecting and reconnecting", i, FormatErrorToStr(dwErrorCode));
			}
			if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
			break;

		case IPC_STATE_WRITING:
			dwErrorCode = HandleMessage(i, &ipc[i]);
			LOGV(L"HandleMessage done.");

			if (dwErrorCode != NO_ERROR) {
				LOGE(L"[IPC%03d] Handle message error: %ls; disconnecting and reconnecting", i, FormatErrorToStr(dwErrorCode));
				if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
				break;
			}

			LOGV(L"[IPC%03d] Writing pipe...", i);
			bReturn = WriteFile(ipc[i].hPipe, ipc[i].chWriteBuf, ipc[i].cbToWrite, &cbReturn, &ipc[i].oOverlap);
			LOGV(L"[IPC%03d] Written pipe.", i);

			// Finished instantly
			if (bReturn && cbReturn == ipc[i].cbToWrite) {
				LOGV(L"[IPC%03d] WriteFile() sent msglen = " WPRDW L" (immediately)", i, cbReturn);
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
				LOGE(L"[IPC%03d] Write() error: %ls or wrote unexpected bytes(" WPRDW L", different from " WPRDW L" as expected); disconnecting and reconnecting", i, FormatErrorToStr(dwErrorCode), cbReturn, ipc[i].cbToWrite);
			}
			if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
			break;

		default:
			LOGE(L"[IPC%03d] Invalid pipe state: " WPRDW L"", i, ipc[i].dwState);
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

static inline int handle_sigint_worker(int sig)
{
	// Once hooked, a cygwin program cannot handle Ctrl-C signal.
	// Thus we have to implement this to kill everything forked
	// by proxychains
	tab_per_process_t* current;
	tab_per_process_t* tmp;
	HANDLE h;

	LOGW(L"[PX:Ctrl-C]");
	fflush(stderr);

	LOCKED({
		HASH_ITER(hh, g_tabPerProcess, current, tmp) {
			HASH_DELETE(hh, g_tabPerProcess, current);
			h = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, current->Data.dwPid);
			if ((h != NULL || h != INVALID_HANDLE_VALUE) && TerminateProcess(h, 0)) {
				LOGW(L"Killed WINPID " WPRDW, current->Data.dwPid);
			}
			else {
				LOGW(L"Unable to kill WINPID " WPRDW, current->Data.dwPid);
			}
			HeapFree(GetProcessHeap(), 0, current);
		}
		exit(0);

		goto after_proc;
	});
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
		handle_sigint_worker(0);
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

DWORD LoadConfiguration(PROXYCHAINS_CONFIG** ppPxchConfig);

DWORD ParseArgs(PROXYCHAINS_CONFIG* pConfig, int argc, WCHAR* argv[], int* piCommandStart);

DWORD Init(void)
{
	g_dwCurrentProcessIdForVerify = GetCurrentProcessId();
	if ((g_hIpcServerSemaphore = CreateSemaphoreW(NULL, 0, 1, NULL)) == NULL) return GetLastError();
	return 0;
}

DWORD InitProcessBookkeeping(void);

#ifndef __CYGWIN__

int wmain(int argc, WCHAR* argv[])
{
	DWORD dwError;
	DWORD dwTid;
	STARTUPINFO startupInfo = { 0 };
	PROCESS_INFORMATION processInformation = { 0 };
	int iCommandStart;

	setvbuf(stderr, NULL, _IOFBF, 65536);
	LOGI(L"Locale: " WPRS, setlocale(LC_ALL, ""));
	if ((dwError = Init()) != NOERROR) goto err;

	if ((dwError = InitProcessBookkeeping()) != NOERROR) goto err;

	if ((dwError = LoadConfiguration(&g_pPxchConfig)) != NOERROR) goto err;

	LOGI(L"DLL Path: %ls", g_pPxchConfig->szHookDllPath);
	LOGI(L"MinHook DLL Path: %ls", g_pPxchConfig->szMinHookDllPath);

	InitHookForMain(g_pPxchConfig);

	if ((dwError = ParseArgs(g_pPxchConfig, argc, argv, &iCommandStart)) != NOERROR) goto err;

	LOGI(L"Config Path: %ls", g_pPxchConfig->szConfigPath);
	LOGI(L"Pipe name: %ls", g_pPxchConfig->szIpcPipeName);
	LOGI(L"Quiet: %ls", g_pPxchConfig->iIsQuiet ? L"Y" : L"N");
	LOGI(L"Command Line: %ls", g_pPxchConfig->szCommandLine);

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

	if (!ProxyCreateProcessW(NULL, g_pPxchConfig->szCommandLine, 0, 0, 0, 0, 0, 0, &startupInfo, &processInformation)) goto err_get;

	SetConsoleCtrlHandler(CtrlHandler, TRUE);
	Sleep(INFINITE);
	return 0;

err_get:
	dwError = GetLastError();
err:
	fwprintf(stderr, L"Error: %ls\n", FormatErrorToStr(dwError));
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
	handle_sigint_worker(sig);
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
	DWORD dwError = 0;
	DWORD dwTid;
	int iCommandStart;
	int i;

	// char* spawn_argv[] = { "bash.exe", NULL };
	WCHAR** wargv = malloc(argc * sizeof(WCHAR*));
	const void* ctx[2];

	setvbuf(stderr, NULL, _IOFBF, 65536);

	for (i = 0; i < argc; i++) {
		int iNeededChars = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
		wargv[i] = malloc(iNeededChars * sizeof(WCHAR));
		MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wargv[i], iNeededChars);
	}

	LOGI(L"Locale: " WPRS, setlocale(LC_ALL, ""));

	if ((dwError = Init()) != NOERROR) goto err;
	if ((dwError = InitProcessBookkeeping()) != NOERROR) goto err;
	if ((dwError = LoadConfiguration(&g_pPxchConfig)) != NOERROR) goto err;

	LOGI(L"DLL Path: %ls", g_pPxchConfig->szHookDllPath);
	LOGI(L"MinHook DLL Path: %ls", g_pPxchConfig->szMinHookDllPath);

	InitHookForMain(g_pPxchConfig);

	if ((dwError = ParseArgs(g_pPxchConfig, argc, wargv, &iCommandStart)) != NOERROR) goto err;

	LOGI(L"Config Path: %ls", g_pPxchConfig->szConfigPath);
	LOGI(L"Pipe name: %ls", g_pPxchConfig->szIpcPipeName);
	LOGI(L"Quiet: %ls", g_pPxchConfig->iIsQuiet ? L"Y" : L"N");
	LOGI(L"argv[iCommandStart]: " WPRS, argv[iCommandStart]);

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
	LOGI(L"Cygwin spawn Tid: " WPRDW, dwTid);
	
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
	fwprintf(stderr, L"Error: %ls\n", FormatErrorToStr(dwError));
	return dwError;
}
#endif