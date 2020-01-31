#include "stdafx.h"
#include <Shlwapi.h>
#ifdef __CYGWIN__
#include <strsafe.h>
#endif
#include <locale.h>
#include <ShellAPI.h>

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

DWORD HandleMessage(int i, IPC_INSTANCE* pipc)
{
	IPC_MSGBUF* pMsg = (IPC_MSGBUF*)pipc->chReadBuf;
	WCHAR sz[IPC_BUFSIZE / sizeof(WCHAR)];

	if (MsgIsType(WSTR, pMsg)) {
		MessageToWstr(sz, *pMsg, pipc->cbRead);
		fwprintf(stderr, L"%ls", sz);
		fflush(stderr);
	}

	WstrToMessage(pipc->chWriteBuf, &pipc->cbToWrite, L"OK");

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

DWORD ServerLoop(PROXYCHAINS_CONFIG* pPxchConfig, HANDLE hProcess)
{
	static IPC_INSTANCE ipc[IPC_INSTANCE_NUM + 1];
	static HANDLE hEvents[IPC_INSTANCE_NUM + 1];
	DWORD dwErrorCode;
	DWORD dwWait;
	DWORD cbReturn;
	BOOL bReturn;
	int i;

	// Initialize
	hEvents[0] = hProcess;
	for (i = 1; i < IPC_INSTANCE_NUM + 1; i++) {
		// Manual-reset, initially signaled event
		hEvents[i] = CreateEventW(NULL, TRUE, TRUE, NULL);
		if (hEvents[i] == 0) goto err_create_event;

		ipc[i].oOverlap.hEvent = hEvents[i];
		ipc[i].hPipe = CreateNamedPipeW(pPxchConfig->szIpcPipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, IPC_INSTANCE_NUM, IPC_BUFSIZE, IPC_BUFSIZE, 0, NULL);

		if (ipc[i].hPipe == INVALID_HANDLE_VALUE) goto err_create_pipe;

		dwErrorCode = ConnectToNewClient(ipc[i].hPipe, &ipc[i].oOverlap);
		if (dwErrorCode != ERROR_IO_PENDING && dwErrorCode != ERROR_PIPE_CONNECTED) return dwErrorCode;

		ipc[i].bPending = (dwErrorCode == ERROR_IO_PENDING);

		ipc[i].dwState = (dwErrorCode == ERROR_PIPE_CONNECTED) ? IPC_STATE_READING : IPC_STATE_CONNECTING;
	}

	LOGD(L"[IPCALL] Waiting for clients...%ls", hProcess == INVALID_HANDLE_VALUE ? L"(not waiting for child process)" : L"");

	while (1) {
		if (hProcess == INVALID_HANDLE_VALUE) {
#ifndef __CYGWIN__
			dwWait = WaitForMultipleObjects(IPC_INSTANCE_NUM, hEvents + 1, FALSE, INFINITE);
#else
			dwWait = WaitForMultipleObjects(IPC_INSTANCE_NUM, hEvents + 1, FALSE, 100);
			if (dwWait == WAIT_TIMEOUT) {
				BOOL bChild = FALSE;
				int iChildPid = 0;
				while ((iChildPid = waitpid((pid_t)(-1), 0, WNOHANG)) > 0) { bChild = TRUE; }
				if (bChild) {
					LOGI(L"Child Process Terminated (between WaitForMultipleObjects()).");
					return 0;
				}
				continue;
			}
#endif
		}
		else {
			dwWait = WaitForMultipleObjects(IPC_INSTANCE_NUM + 1, hEvents, FALSE, INFINITE);

		}

		i = dwWait - WAIT_OBJECT_0;
		if (hProcess == INVALID_HANDLE_VALUE && i >= 0) {
			i++;
		}
		if (i < 0 || i > IPC_INSTANCE_NUM + 1) goto err_wait_out_of_range;

		if (i == 0) {
			// Child process terminated
			LOGD(L"Child process terminated");
			return 0;
		}

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

			if (dwErrorCode != NO_ERROR) {
				LOGE(L"[IPC%03d] Handle message error: %ls; disconnecting and reconnecting", i, FormatErrorToStr(dwErrorCode));
				if ((dwErrorCode = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwErrorCode;
				break;
			}

			bReturn = WriteFile(ipc[i].hPipe, ipc[i].chWriteBuf, ipc[i].cbToWrite, &cbReturn, &ipc[i].oOverlap);

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

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
		wprintf(L"Ctrl-C event");
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

	dwRet = GetModuleFileNameW(NULL, pPxchConfig->szDllPath, MAX_DLL_PATH_BUFSIZE);
	if (dwRet == 0) goto err_insuf_buf;
	if (dwRet == MAX_DLL_PATH_BUFSIZE) goto err_insuf_buf;

	if (!PathRemoveFileSpecW(pPxchConfig->szDllPath)) goto err_insuf_buf;

	if (FAILED(StringCchCatW(pPxchConfig->szDllPath, MAX_DLL_PATH_BUFSIZE, L"\\"))) goto err_insuf_buf;
	if (FAILED(StringCchCopyW(pPxchConfig->szMinHookDllPath, MAX_DLL_PATH_BUFSIZE, pPxchConfig->szDllPath))) goto err_insuf_buf;
	if (FAILED(StringCchCatW(pPxchConfig->szDllPath, MAX_DLL_PATH_BUFSIZE, g_szDllFileName))) goto err_insuf_buf;
	if (FAILED(StringCchCatW(pPxchConfig->szMinHookDllPath, MAX_DLL_PATH_BUFSIZE, g_szMinHookDllFileName))) goto err_insuf_buf;

	if (!PathFileExistsW(pPxchConfig->szDllPath)) goto err_dll_not_exist;
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

#ifndef __CYGWIN__

int wmain(int argc, WCHAR* argv[])
{
	PROXYCHAINS_CONFIG config = { 0 };
	DWORD dwError;
	STARTUPINFO startupInfo = { 0 };
	PROCESS_INFORMATION processInformation = { 0 };
	int iCommandStart;

	g_pPxchConfig = &config;

	setvbuf(stderr, NULL, _IOFBF, 65536);

#ifdef __CYGWIN__
	LOGI(L"Locale: %s", setlocale(LC_ALL, ""));
#else
	LOGI(L"Locale: %S", setlocale(LC_ALL, ""));
#endif
	// SetConsoleCtrlHandler(CtrlHandler, TRUE);

	if ((dwError = LoadConfiguration(&config)) != NOERROR) goto err;

	LOGI(L"DLL Path: %ls", config.szDllPath);
	LOGI(L"MinHook DLL Path: %ls", config.szMinHookDllPath);

	InitHookForMain(&config);

	if ((dwError = ParseArgs(g_pPxchConfig, argc, argv, &iCommandStart)) != NOERROR) goto err;

	LOGI(L"Config Path: %ls", config.szConfigPath);
	LOGI(L"Pipe name: %ls", config.szIpcPipeName);
	LOGI(L"Quiet: %ls", config.bQuiet ? L"Y" : L"N");
	LOGI(L"Command Line: %ls", config.szCommandLine);

	ProxyCreateProcessW(NULL, config.szCommandLine, 0, 0, 1, 0, 0, 0, &startupInfo, &processInformation);
	//CreateProcessW(NULL, config.szCommandLine, 0, 0, 1, 0, 0, 0, &startupInfo, &processInformation);

	// WaitForSingleObject(processInformation.hProcess, INFINITE);
	// ServerLoop(g_pPxchConfig, processInformation.hProcess);
	ServerLoop(g_pPxchConfig, INVALID_HANDLE_VALUE);

	return 0;

err:
	PrintErrorToFile(stderr, dwError);
	return dwError;
}

#else 

void handle_sigchld(int sig)
{
	while (waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
	LOGI(L"Child Process Terminated.");
	exit(0);
}

void handle_sigint(int sig)
{
	fwprintf(stderr, L"[PX:Ctrl-C]");
	fflush(stderr);
}

int main(int argc, char* const argv[], char* const envp[])
{
	PROXYCHAINS_CONFIG config = { 0 };
	DWORD dwError = 0;
	pid_t child_pid;
	int iCommandStart;
	int i;
	int iReturn;
	// char* spawn_argv[] = { "bash.exe", NULL };
	WCHAR** wargv = malloc(argc * sizeof(WCHAR*));

	g_pPxchConfig = &config;

	// signal(SIGINT, handle_sigint);
	setvbuf(stderr, NULL, _IOFBF, 65536);

	for (i = 0; i < argc; i++) {
		int iNeededChars = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
		wargv[i] = malloc(iNeededChars * sizeof(WCHAR));
		MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wargv[i], iNeededChars);
	}

	LOGI(L"Locale: %s", setlocale(LC_ALL, ""));

	if ((dwError = LoadConfiguration(&config)) != NOERROR) goto err;

	LOGI(L"DLL Path: %ls", config.szDllPath);
	LOGI(L"MinHook DLL Path: %ls", config.szMinHookDllPath);

	InitHookForMain(&config);

	if ((dwError = ParseArgs(g_pPxchConfig, argc, wargv, &iCommandStart)) != NOERROR) goto err;

	LOGI(L"Config Path: %ls", config.szConfigPath);
	LOGI(L"Quiet: %ls", config.bQuiet ? L"Y" : L"N");
	LOGI(L"argv[iCommandStart]: %s", argv[iCommandStart]);

	iReturn = posix_spawnp(&child_pid, argv[iCommandStart], NULL, NULL, &argv[iCommandStart], envp);
	LOGD(L"Spawn ret: %d; CYGPID: " WPRDW L"", iReturn, child_pid);

	signal(SIGCHLD, handle_sigchld);
	ServerLoop(g_pPxchConfig, INVALID_HANDLE_VALUE);

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

err:
	PrintErrorToFile(stderr, dwError);
	return dwError;
}
#endif