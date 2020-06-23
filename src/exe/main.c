// SPDX-License-Identifier: GPL-2.0-or-later
/* main.c
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
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#include "version.h"
#include "includes_win32.h"
#include <ShellAPI.h>
#include <Sddl.h>

#include <strsafe.h>

#include "log_win32.h"
#include "proc_bookkeeping_win32.h"
#include "hookdll_win32.h"
#include "hookdll_util_win32.h"

#ifdef __CYGWIN__
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <spawn.h>
#include <process.h>
#endif

HANDLE g_hIpcServerSemaphore;

DWORD HandleMessage(int i, PXCH_IPC_INSTANCE* pipc);

DWORD ConnectToNewClient(HANDLE hPipe, LPOVERLAPPED lpo)
{
	BOOL bConnected;
	DWORD dwLastError;

	bConnected = ConnectNamedPipe(hPipe, lpo);
	dwLastError = GetLastError();

	// Should return zero because it's overlapped
	if (bConnected != 0) goto err_connected_not_zero;


	switch (dwLastError) {
	case ERROR_IO_PENDING:
		return ERROR_IO_PENDING;

	case ERROR_PIPE_CONNECTED:
		if (!SetEvent(lpo->hEvent)) goto err_set_event;
		return ERROR_PIPE_CONNECTED;

	default:
		goto err_other_codes;
	}

err_set_event:
	LOGE(L"Error signaling event: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;

err_other_codes:
err_connected_not_zero:
	LOGE(L"Error connecting pipe: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;
}

DWORD DisconnectAndReconnect(PXCH_IPC_INSTANCE* ipc, int i)
{
	DWORD dwLastError;

	if (!DisconnectNamedPipe(ipc[i].hPipe)) {
		LOGE(L"[IPC%03d] disconnect failed: %ls.", i, FormatErrorToStr(GetLastError()));
	}

	dwLastError = ConnectToNewClient(ipc[i].hPipe, &ipc[i].oOverlap);
	if (dwLastError != ERROR_IO_PENDING && dwLastError != ERROR_PIPE_CONNECTED) return dwLastError;

	ipc[i].bPending = (dwLastError == ERROR_IO_PENDING);
	ipc[i].dwState = (dwLastError == ERROR_PIPE_CONNECTED) ? PXCH_IPC_STATE_READING : PXCH_IPC_STATE_CONNECTING;
	return 0;
}

DWORD WINAPI ServerLoop(LPVOID lpVoid)
{
	static PXCH_IPC_INSTANCE ipc[PXCH_IPC_INSTANCE_NUM];
	static HANDLE hEvents[PXCH_IPC_INSTANCE_NUM];
	PROXYCHAINS_CONFIG* pPxchConfig = (PROXYCHAINS_CONFIG*)lpVoid;
	DWORD dwLastError;
	DWORD dwWait;
	DWORD cbReturn;
	BOOL bReturn;
	int i;
	SECURITY_ATTRIBUTES SecAttr;
	PSECURITY_DESCRIPTOR pSecDesc;

	LOGV(L"Ipc Server Initializing...");

	// https://docs.microsoft.com/zh-cn/windows/win32/secauthz/security-descriptor-string-format
	// https://stackoverflow.com/questions/9589141/low-integrity-to-medium-high-integrity-pipe-security-descriptor
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;0x12019f;;;WD)S:(ML;;NW;;;LW)", SDDL_REVISION_1, &pSecDesc, NULL)) {
		if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;0x12019f;;;WD)", SDDL_REVISION_1, &pSecDesc, NULL)) {
			dwLastError = GetLastError();
			LOGE(L"Initializing Security Descriptor error: %ls", FormatErrorToStr(dwLastError));
			return dwLastError;
		}
	}

	SecAttr.nLength = sizeof(SecAttr);
	SecAttr.bInheritHandle = FALSE;
	SecAttr.lpSecurityDescriptor = pSecDesc;

	// Initialize
	for (i = 0; i < PXCH_IPC_INSTANCE_NUM; i++) {
		// Manual-reset, initially signaled event
		LOGV(L"Ipc Server Initializing Event %d", i);
		hEvents[i] = CreateEventW(NULL, TRUE, TRUE, NULL);
		if (hEvents[i] == 0) goto err_create_event;

		ipc[i].oOverlap.hEvent = hEvents[i];

		ipc[i].hPipe = CreateNamedPipeW(pPxchConfig->szIpcPipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PXCH_IPC_INSTANCE_NUM, PXCH_IPC_BUFSIZE, PXCH_IPC_BUFSIZE, 0, &SecAttr);

		if (ipc[i].hPipe == INVALID_HANDLE_VALUE) goto err_create_pipe;

		dwLastError = ConnectToNewClient(ipc[i].hPipe, &ipc[i].oOverlap);
		if (dwLastError != ERROR_IO_PENDING && dwLastError != ERROR_PIPE_CONNECTED) return dwLastError;

		ipc[i].bPending = (dwLastError == ERROR_IO_PENDING);

		ipc[i].dwState = (dwLastError == ERROR_PIPE_CONNECTED) ? PXCH_IPC_STATE_READING : PXCH_IPC_STATE_CONNECTING;
	}

	LocalFree(pSecDesc);

	LOGD(L"[IPCALL] Waiting for clients...");
	LOGV(L"ServerLoop: Signaling semaphore...");
	if (!ReleaseSemaphore(g_hIpcServerSemaphore, 1, NULL)) {
		dwLastError = GetLastError();
		LOGC(L"Release semaphore error: %ls", FormatErrorToStr(dwLastError));
		exit(dwLastError);
	}
	// CloseHandle(g_hIpcServerSemaphore);
	LOGV(L"ServerLoop: Signaled semaphore.");

	while (1) {
#ifndef __CYGWIN__
		dwWait = WaitForMultipleObjects(PXCH_IPC_INSTANCE_NUM, hEvents, FALSE, INFINITE);
#else
		dwWait = WaitForMultipleObjects(PXCH_IPC_INSTANCE_NUM, hEvents, FALSE, 100);
		if (dwWait == WAIT_TIMEOUT) {
			BOOL bChild = FALSE;
			int iChildPid;
			int iChildPidTmp;
			int iChildStatus;
			int iChildStatusTmp;
			BOOL bChildExitedNormally;
			int iChildExitStatus;

			while ((iChildPidTmp = waitpid((pid_t)(-1), &iChildStatusTmp, WNOHANG)) > 0) {
				bChild = TRUE;
				iChildStatus = iChildStatusTmp;
				iChildPid = iChildPidTmp;
			}

			if (bChild) {
				bChildExitedNormally = WIFEXITED(iChildStatus);
				iChildExitStatus = WEXITSTATUS(iChildStatus);

				if (iChildExitStatus == 127) {
					LOGE(L"Cygwin child process pid %d exited %ls(%d) (between WaitForMultipleObjects()). YOUR COMMAND LINE MAY HAVE ERROR. Master exiting", iChildPid, bChildExitedNormally ? L"normally" : L"ABNORMALLY", iChildExitStatus);
				} else {
					LOGI(L"Cygwin child process pid %d exited %ls(%d) (between WaitForMultipleObjects()). Master exiting", iChildPid, bChildExitedNormally ? L"normally" : L"ABNORMALLY", iChildExitStatus);
				}
				IF_CYGWIN_EXIT(iChildExitStatus);
			}
			continue;
		}
#endif
		i = dwWait - WAIT_OBJECT_0;
		if (i < 0 || i >= PXCH_IPC_INSTANCE_NUM) goto err_wait_out_of_range;

		// If this pipe is just awaken from pending state
		if (ipc[i].bPending) {
			bReturn = GetOverlappedResult(ipc[i].hPipe, &ipc[i].oOverlap, &cbReturn, FALSE);

			switch (ipc[i].dwState) {
			case PXCH_IPC_STATE_CONNECTING:
				if (!bReturn) goto err_connect_overlapped_error;
				LOGV(L"[IPC%03d] named pipe connected.", i);
				ipc[i].dwState = PXCH_IPC_STATE_READING;
				break;

			case PXCH_IPC_STATE_READING:
				if (!bReturn || cbReturn == 0) {
					dwLastError = GetLastError();
					if (dwLastError != ERROR_BROKEN_PIPE) {
						LOGE(L"[IPC%03d] GetOverlappedResult() error(" WPRDW L") or read 0 bytes(" WPRDW L"), disconnect and reconnecting", i, dwLastError, cbReturn);
					}
					if ((dwLastError = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwLastError;
					continue;
				}
				LOGV(L"[IPC%03d] ReadFile() received msglen = " WPRDW L"", i, cbReturn);
				ipc[i].cbRead = cbReturn;
				ipc[i].dwState = PXCH_IPC_STATE_WRITING;
				break;

			case PXCH_IPC_STATE_WRITING:
				if (!bReturn || cbReturn != ipc[i].cbToWrite) {
					dwLastError = GetLastError();
					if (dwLastError != ERROR_BROKEN_PIPE) {
						LOGE(L"[IPC%03d] GetOverlappedResult() error(" WPRDW L") or wrote " WPRDW L" bytes (!= " WPRDW L" as expected), disconnect and reconnecting", i, dwLastError, cbReturn, ipc[i].cbToWrite);
					}
					if ((dwLastError = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwLastError;
					continue;
				}
				LOGV(L"[IPC%03d] WriteFile() sent msglen = " WPRDW L"", i, cbReturn);
				ipc[i].dwState = PXCH_IPC_STATE_READING;
				break;

			default:
				LOGE(L"[IPC%03d] Invalid pipe state: " WPRDW L"", i, ipc[i].dwState);
				return ERROR_INVALID_STATE;
			}
		}

		// Last operation has finished, now dwState stores what to do next
		switch (ipc[i].dwState) {
		case PXCH_IPC_STATE_READING:
			bReturn = ReadFile(ipc[i].hPipe, ipc[i].chReadBuf, PXCH_IPC_BUFSIZE, &ipc[i].cbRead, &ipc[i].oOverlap);

			// Finished instantly
			if (bReturn && ipc[i].cbRead != 0) {
				LOGV(L"[IPC%03d] ReadFile() received msglen = " WPRDW L" (immediately)", i, ipc[i].cbRead);
				ipc[i].bPending = FALSE;
				ipc[i].dwState = PXCH_IPC_STATE_WRITING;
				continue;
			}

			// Pending
			dwLastError = GetLastError();
			if (!bReturn && (dwLastError == ERROR_IO_PENDING)) {
				ipc[i].bPending = TRUE;
				continue;
			}

			if (dwLastError != ERROR_BROKEN_PIPE) {
				LOGE(L"[IPC%03d] ReadFile() error: %ls or has read 0 bytes; disconnecting and reconnecting", i, FormatErrorToStr(dwLastError));
			}
			if ((dwLastError = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwLastError;
			break;

		case PXCH_IPC_STATE_WRITING:
			dwLastError = HandleMessage(i, &ipc[i]);
			LOGV(L"HandleMessage done.");

			if (dwLastError != NO_ERROR) {
				LOGE(L"[IPC%03d] Handle message error: %ls; disconnecting and reconnecting", i, FormatErrorToStr(dwLastError));
				if ((dwLastError = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwLastError;
				break;
			}

			LOGV(L"[IPC%03d] Writing pipe...", i);
			bReturn = WriteFile(ipc[i].hPipe, ipc[i].chWriteBuf, ipc[i].cbToWrite, &cbReturn, &ipc[i].oOverlap);
			LOGV(L"[IPC%03d] Written pipe.", i);

			// Finished instantly
			if (bReturn && cbReturn == ipc[i].cbToWrite) {
				LOGV(L"[IPC%03d] WriteFile() sent msglen = " WPRDW L" (immediately)", i, cbReturn);
				ipc[i].bPending = FALSE;
				ipc[i].dwState = PXCH_IPC_STATE_READING;
				continue;
			}

			// Pending
			dwLastError = GetLastError();
			if (!bReturn && (dwLastError == ERROR_IO_PENDING)) {
				ipc[i].bPending = TRUE;
				continue;
			}

			if (dwLastError != ERROR_BROKEN_PIPE) {
				LOGE(L"[IPC%03d] Write() error: %ls or wrote unexpected bytes(" WPRDW L", different from " WPRDW L" as expected); disconnecting and reconnecting", i, FormatErrorToStr(dwLastError), cbReturn, ipc[i].cbToWrite);
			}
			if ((dwLastError = DisconnectAndReconnect(ipc, i)) != NO_ERROR) return dwLastError;
			break;

		default:
			LOGE(L"[IPC%03d] Invalid pipe state: " WPRDW L"", i, ipc[i].dwState);
			return ERROR_INVALID_STATE;
		}
	}
	return 0;

err_create_event:
	dwLastError = GetLastError();
	LOGE(L"Error creating event: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;

err_create_pipe:
	dwLastError = GetLastError();
	LOGE(L"Error creating pipe: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;

err_wait_out_of_range:
	dwLastError = GetLastError();
	LOGE(L"WaitForMultipleObjects() out of range: %d, last error: %ls", i, FormatErrorToStr(dwLastError));
	return ERROR_DS_RANGE_CONSTRAINT;

err_connect_overlapped_error:
	dwLastError = GetLastError();
	LOGE(L"[IPC%03d] GetOverlappedResult() error: %ls", i, FormatErrorToStr(dwLastError));
	return dwLastError;

}

void PrintUsage(const WCHAR* szArgv0, BOOL bError)
{
	static const WCHAR* szUsage =
		L"Proxychains.exe "
#ifdef __CYGWIN__
		L"Cygwin"
#else
		L"Win32"
#endif
		L" "
#if defined(_M_X64) || defined(__x86_64__)
		L"64-bit"
#else
		L"32-bit"
#endif
		L" "
#if defined(DEBUG)
		L"Debug"
#else
		L"Release"
#endif
		L" %u.%u.%u - proxifier for Win32 and Cygwin.\n"
		L"\n"
		L"Usage: "
#ifdef __CYGWIN__
		L"[PROXYCHAINS_CONF_FILE=<CUSTOM_CONFIG_FILE>] "
#endif
		L"%ls [-q] [-Q] [-f <CUSTOM_CONFIG_FILE>] [-l <LOG_LEVEL>] <PROGRAM_NAME> <ARGUMENTS>...\n"
		L"\n"
		L" -q              Forces quiet (not printing any information except errors)\n"
		L" -Q              Forces non-quiet (ignoring quiet option in configuration files)\n"
		L" -f              Manually specify a configuration file.\n"
		L"                 By default, configuration file is searched in:\n"
#ifdef __CYGWIN__
		L"                  - $HOME/.proxychains/proxychains.conf\n"
		L"                  - (SYSCONFDIR)/proxychains.conf\n"
		L"                  - /etc/proxychains.conf\n"
#else
		L"                  - %%USERPROFILE%%\\.proxychains\\proxychains.conf\n"
		L"                  - (Roaming directory of current user)\\Proxychains\\proxychains.conf\n"
		L"                  - (Global ProgramData directory)\\Proxychains\\proxychains.conf\n"
#endif
		L" -l <LOG_LEVEL>  Manually set log level. <LOG_LEVEL> can be:\n"
		L"                  - V/VERBOSE\n"
		L"                  - D/DEBUG\n"
		L"                  - I/INFO\n"
		L"                  - W/WARNING\n"
		L"                  - E/ERROR\n"
		L"                  - C/CRITICAL\n"
		L"                 Note that some levels are always unavailable in a Release build.\n";

	if (bError) {
		fwprintf(stderr, szUsage, PXCH_VERSION_MAJOR, PXCH_VERSION_MINOR, PXCH_VERSION_PATCH, szArgv0);
		fflush(stderr);
	} else {
		fwprintf(stdout, szUsage, PXCH_VERSION_MAJOR, PXCH_VERSION_MINOR, PXCH_VERSION_PATCH, szArgv0);
		fflush(stdout);
	}
}

void KillAllDescendant()
{
	// Once hooked, a cygwin program cannot handle Ctrl-C signal.
	// Thus we have to implement this to kill everything forked
	// by proxychains
	tab_per_process_t* current;
	tab_per_process_t* tmp;
	HANDLE h;

	PXCH_DO_IN_CRITICAL_SECTION_RETURN_VOID{
		HASH_ITER(hh, g_tabPerProcess, current, tmp) {
			HASH_DELETE(hh, g_tabPerProcess, current);
			h = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, current->Data.dwPid);
			if ((h != NULL || h != INVALID_HANDLE_VALUE) && TerminateProcess(h, 0)) {
				LOGD(L"Killed WINPID " WPRDW, current->Data.dwPid);
			}
			else {
				LOGD(L"Unable to kill WINPID " WPRDW, current->Data.dwPid);
			}
			HeapFree(GetProcessHeap(), 0, current);
		}
	}
}

void handle_sigint(int sig)
{
	LOGW(L"[PX:Ctrl-C]");
	fflush(stderr);

#ifndef __CYGWIN__
	KillAllDescendant();
	exit(STATUS_CONTROL_C_EXIT);
#endif
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
		handle_sigint(0);
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

DWORD LoadConfiguration(PROXYCHAINS_CONFIG** ppPxchConfig, PROXYCHAINS_CONFIG* pTempPxchConfig);
void PrintConfiguration(PROXYCHAINS_CONFIG* pPxchConfig);
DWORD ParseArgs(PROXYCHAINS_CONFIG* pConfig, int argc, WCHAR* argv[], int* piCommandStart);

DWORD Init(void)
{
	g_dwCurrentProcessIdForVerify = GetCurrentProcessId();
	if ((g_hIpcServerSemaphore = CreateSemaphoreW(NULL, 0, 1, NULL)) == NULL) return GetLastError();
	if ((g_hCygwinConsoleSemaphore = CreateSemaphoreW(NULL, 1, 1, NULL)) == NULL) return GetLastError();
	return 0;
}

DWORD InitProcessBookkeeping(void);

#if !defined(__CYGWIN__) || defined(PXCH_MSYS_USE_WIN32_STYLE)
#if defined(PXCH_MSYS_USE_WIN32_STYLE)
int main(int argc, char* argv[])
#else
int wmain(int argc, WCHAR* wargv[])
#endif
{
	DWORD dwError;
	DWORD dwTid;
	STARTUPINFO startupInfo = { 0 };
	PROCESS_INFORMATION ProcessInformation = { 0 };
	PROXYCHAINS_CONFIG TempProxychainsConfig;
	int iCommandStart;
	const char* szLocale;
#if defined(PXCH_MSYS_USE_WIN32_STYLE)
	WCHAR** wargv;
#endif

#if defined(PXCH_MSYS_USE_WIN32_STYLE)
	{
		int i;
		wargv = malloc(argc * sizeof(WCHAR*));

		for (i = 0; i < argc; i++) {
			int iNeededChars = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
			wargv[i] = malloc(iNeededChars * sizeof(WCHAR));
			MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wargv[i], iNeededChars);
		}
	}
#endif

	setvbuf(stderr, NULL, _IOFBF, 65536);
	szLocale = setlocale(LC_ALL, "");

	if ((dwError = Init()) != NOERROR) goto err;
	if ((dwError = InitProcessBookkeeping()) != NOERROR) goto err;
	if ((dwError = ParseArgs(&TempProxychainsConfig, argc, wargv, &iCommandStart)) != NOERROR) goto err_args;
	if ((dwError = LoadConfiguration(&g_pPxchConfig, &TempProxychainsConfig)) != NOERROR) goto err;
	if (g_pPxchConfig->dwLogLevel >= PXCH_LOG_LEVEL_DEBUG) PrintConfiguration(g_pPxchConfig);

	InitHookForMain(g_pPxchConfig);


	if (CreateThread(0, 0, &ServerLoop, g_pPxchConfig, 0, &dwTid) == NULL) goto err_get;
	LOGD(L"IPC Server Tid: " WPRDW, dwTid);

	if (g_hIpcServerSemaphore != NULL) {
		DWORD dwWaitResult;
		DWORD dwLastError;

		LOGV(L"Waiting for g_hIpcServerSemaphore.");

		dwWaitResult = WaitForSingleObject(g_hIpcServerSemaphore, INFINITE);
		switch (dwWaitResult)
		{
		case WAIT_OBJECT_0:
			if (!ReleaseSemaphore(g_hIpcServerSemaphore, 1, NULL)) {
				dwLastError = GetLastError();
				LOGC(L"Release semaphore error: %ls", FormatErrorToStr(dwLastError));
				exit(dwLastError);
			}
			CloseHandle(g_hIpcServerSemaphore);
			g_hIpcServerSemaphore = NULL;
			break;

		case WAIT_ABANDONED:
			LOGC(L"Semaphore abandoned!");
			Sleep(INFINITE);
			exit(ERROR_ABANDONED_WAIT_0);
			break;

		default:
			dwLastError = GetLastError();
			LOGW(L"Wait for semaphore status: " WPRDW L"; error: %ls", dwWaitResult, FormatErrorToStr(dwLastError));
			exit(dwLastError);
		}
	}

	LOGD(L"szCommandLine: %ls", g_pPxchConfig->szCommandLine);
	if (!ProxyCreateProcessW(NULL, g_pPxchConfig->szCommandLine, 0, 0, 0, 0, 0, 0, &startupInfo, &ProcessInformation)) goto err_get;

	if (g_tabPerProcess == NULL) {
		LOGI(L"No child process registered. Injection might not have succeeded.");
		WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
		IF_WIN32_EXIT(127);
	} else {
		SetConsoleCtrlHandler(CtrlHandler, TRUE);
		Sleep(INFINITE);
	}
	return 0;

err_get:
	dwError = GetLastError();
err:
	fwprintf(stderr, L"Error: %ls\n", FormatErrorToStr(dwError));
	fflush(stderr);	// Must flush, otherwise display messy code on xp
	return dwError;

err_args:
	PrintUsage(wargv[0], dwError != ERROR_CANCELLED);
	return dwError == ERROR_CANCELLED ? 0 : dwError;
}

#else 

void handle_sigchld(int sig)
{
	BOOL bChild = FALSE;
	int iChildPid;
	int iChildPidTmp;
	int iChildStatus;
	int iChildStatusTmp;
	BOOL bChildExitedNormally;
	int iChildExitStatus;
	DWORD dwWaitResult;
	DWORD dwLastError;

	while ((iChildPidTmp = waitpid((pid_t)(-1), &iChildStatusTmp, WNOHANG)) > 0) {
		bChild = TRUE;
		iChildStatus = iChildStatusTmp;
		iChildPid = iChildPidTmp;
	}

	if (bChild) {
		bChildExitedNormally = WIFEXITED(iChildStatus);
		iChildExitStatus = WEXITSTATUS(iChildStatus);

		if (iChildExitStatus == 127) {
			LOGE(L"Cygwin child process pid %d exited %ls(%d). YOUR COMMAND LINE MAY HAVE ERROR.", iChildPid, bChildExitedNormally ? L"normally" : L"ABNORMALLY", iChildExitStatus);
		} else {
			LOGI(L"Cygwin child process pid %d exited %ls(%d).", iChildPid, bChildExitedNormally ? L"normally" : L"ABNORMALLY", iChildExitStatus);
		}

		// KillAllDescendant();

		// Close cygwin console semaphore
		dwWaitResult = WaitForSingleObject(g_hCygwinConsoleSemaphore, INFINITE);
		switch (dwWaitResult)
		{
		case WAIT_OBJECT_0:
			break;

		case WAIT_ABANDONED:
			LOGC(L"g_hCygwinConsoleSemaphore abandoned!");
			Sleep(INFINITE);
			exit(ERROR_ABANDONED_WAIT_0);
			break;

		default:
			dwLastError = GetLastError();
			LOGE(L"Wait for g_hCygwinConsoleSemaphore status: " WPRDW L"; error: %ls", dwWaitResult, FormatErrorToStr(dwLastError));
			exit(dwLastError);
		}

		exit(iChildExitStatus);
	}
}

#define PXCH_CYGWIN_USE_SPAWNVPE_INSTEAD_OF_FORK_EXEC 0
DWORD WINAPI CygwinSpawn(LPVOID lpParam)
{
	void** ctx = lpParam;
	pid_t child_pid = 0;
	char*const* p_argv_command_start = ctx[0];
	char*const* envp = ctx[1];
	int iReturn = 0;

#if PXCH_CYGWIN_USE_SPAWNVPE_INSTEAD_OF_FORK_EXEC
	iReturn = spawnvpe(_P_NOWAIT, (const char*)*p_argv_command_start, (const char*const*)p_argv_command_start, (const char*const*)envp);
#else
	iReturn = posix_spawnp(&child_pid, *p_argv_command_start, NULL, NULL, p_argv_command_start, envp);
#endif

	if (child_pid == 0) {
		child_pid = (pid_t)iReturn;
	}
#if PXCH_CYGWIN_USE_SPAWNVPE_INSTEAD_OF_FORK_EXEC
	LOGI(L"spawnvpe ret: %d; CYGPID: " WPRDW L"", iReturn, child_pid);
#else
	LOGI(L"posix_spawnp ret: %d; CYGPID: " WPRDW L"", iReturn, child_pid);
#endif

	return iReturn < 0 ? ERROR_OPEN_FAILED : 0;
}

int main(int argc, char* const argv[], char* const envp[])
{
	DWORD dwError = 0;
	DWORD dwTid;
	int iCommandStart;
	int i;
	const char* szLocale;
	PROXYCHAINS_CONFIG TempProxychainsConfig;

	WCHAR** wargv = malloc(argc * sizeof(WCHAR*));
	const void* ctx[2];

	setvbuf(stderr, NULL, _IOFBF, 65536);

	for (i = 0; i < argc; i++) {
		int iNeededChars = MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, NULL, 0);
		wargv[i] = malloc(iNeededChars * sizeof(WCHAR));
		MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, wargv[i], iNeededChars);
	}

	setvbuf(stderr, NULL, _IOFBF, 65536);
	szLocale = setlocale(LC_ALL, "");
	(void)szLocale;

	if ((dwError = Init()) != NOERROR) goto err;
	if ((dwError = InitProcessBookkeeping()) != NOERROR) goto err;
	if ((dwError = ParseArgs(&TempProxychainsConfig, argc, wargv, &iCommandStart)) != NOERROR) goto err_args;
	if ((dwError = LoadConfiguration(&g_pPxchConfig, &TempProxychainsConfig)) != NOERROR) goto err;
	if (g_pPxchConfig->dwLogLevel >= PXCH_LOG_LEVEL_DEBUG) PrintConfiguration(g_pPxchConfig);
	InitHookForMain(g_pPxchConfig);

	if (CreateThread(0, 0, &ServerLoop, g_pPxchConfig, 0, &dwTid) == NULL) goto err_get;
	LOGD(L"IPC Server Tid: " WPRDW, dwTid);

	if (g_hIpcServerSemaphore != NULL) {
		DWORD dwWaitResult;
		DWORD dwLastError;

		LOGV(L"Waiting for g_hIpcServerSemaphore.");

		dwWaitResult = WaitForSingleObject(g_hIpcServerSemaphore, INFINITE);
		switch (dwWaitResult)
		{
		case WAIT_OBJECT_0:
			if (!ReleaseSemaphore(g_hIpcServerSemaphore, 1, NULL)) {
				dwLastError = GetLastError();
				LOGC(L"Release semaphore error: %ls", FormatErrorToStr(dwLastError));
				exit(dwLastError);
			}
			CloseHandle(g_hIpcServerSemaphore);
			g_hIpcServerSemaphore = NULL;
			break;

		case WAIT_ABANDONED:
			LOGC(L"Semaphore abandoned!");
			Sleep(INFINITE);
			exit(ERROR_ABANDONED_WAIT_0);
			break;

		default:
			dwLastError = GetLastError();
			LOGW(L"Wait for semaphore status: " WPRDW L"; error: %ls", dwWaitResult, FormatErrorToStr(dwLastError));
			exit(dwLastError);
		}
	}

	LOGD(L"iCommandStart: %d", iCommandStart);
	ctx[0] = &argv[iCommandStart];
	ctx[1] = envp;

	if (CygwinSpawn(ctx) != NO_ERROR) {
		LOGE(L"Spawn child process failed.");
		return 1;
	}

	if (g_tabPerProcess == NULL) {
		LOGI(L"No child process registered. Injection might not have succeeded.");
		IF_CYGWIN_EXIT(127);
	}

	signal(SIGINT, handle_sigint);
	signal(SIGCHLD, handle_sigchld);

	while(1) pause();
	return 0;

err_get:
	dwError = GetLastError();
err:
	fwprintf(stderr, L"Error: %ls\n", FormatErrorToStr(dwError));
	return dwError;

err_args:
	PrintUsage(wargv[0], dwError != ERROR_CANCELLED);
	return dwError == ERROR_CANCELLED ? 0 : dwError;
}
#endif