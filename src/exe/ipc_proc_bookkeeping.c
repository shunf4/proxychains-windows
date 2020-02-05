#include "includes_win32.h"
#include "log_win32.h"
#include "hookdll_win32.h"
#include "proc_bookkeeping_win32.h"


tab_per_process_t* g_tabPerProcess;
HANDLE g_hDataMutex;
tab_fake_ip_hostname_t* g_tabFakeIpHostname;


DWORD ChildProcessExitedCallbackWorker(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
	LOCKED({
		tab_per_process_t * entry = (tab_per_process_t*)lpParameter;
		DWORD dwExitCode = UINT32_MAX;
		HASH_DELETE(hh, g_tabPerProcess, entry);
		if (!GetExitCodeProcess(entry->hProcess, &dwExitCode)) {
			LOGE(L"GetExitCodeProcess() error: %ls", FormatErrorToStr(GetLastError()));
		}
		LOGI(L"Child process winpid " WPRDW L" exited (%#010x).", entry->Data.dwPid, dwExitCode);
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
		if ((hChildHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pChildData->dwPid)) == NULL) {
			dwReturn = GetLastError();
			if (dwReturn == ERROR_ACCESS_DENIED) {
				if ((hChildHandle = OpenProcess(SYNCHRONIZE, FALSE, pChildData->dwPid)) == NULL) {
					dwReturn = GetLastError();
				} else {
					goto after_open_process;
				}
			}
			LOGC(L"OpenProcess() error: %ls", FormatErrorToStr(dwReturn));
			goto after_proc;
		}
	after_open_process:
		LOGD(L"After OpenProcess(" WPRDW L")...", hChildHandle);

		if (!RegisterWaitForSingleObject(&hWaitHandle, hChildHandle, &ChildProcessExitedCallback, entry, INFINITE, WT_EXECUTELONGFUNCTION | WT_EXECUTEONLYONCE)) {
			dwReturn = GetLastError();
			LOGC(L"RegisterWaitForSingleObject() error: %ls", FormatErrorToStr(dwReturn));
			goto after_proc;
		}
		LOGV(L"After RegisterWaitForSingleObject...");
		entry->Data = *pChildData;
		entry->hProcess = hChildHandle;
		LOGV(L"After entry->Data = *pChildData;");
		HASH_ADD(hh, g_tabPerProcess, Data, sizeof(pid_key_t), entry);
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
			*pChildData = entry->Data;
		}

		goto after_proc;
	});
}

DWORD HandleMessage(int i, IPC_INSTANCE* pipc)
{
	IPC_MSGBUF* pMsg = (IPC_MSGBUF*)pipc->chReadBuf;

	if (MsgIsType(WSTR, pMsg)) {
		WCHAR sz[IPC_BUFSIZE / sizeof(WCHAR)];
		MessageToWstr(sz, *pMsg, pipc->cbRead);
		StdWprintf(STD_ERROR_HANDLE, L"%ls", sz);
		StdFlush(STD_ERROR_HANDLE);

		goto after_handling_resp_ok;
	}

	if (MsgIsType(CHILDDATA, pMsg)) {
		REPORTED_CHILD_DATA childData;
		LOGV(L"Message is CHILDDATA");
		MessageToChildData(&childData, *pMsg, pipc->cbRead);
		LOGD(L"Child process pid " WPRDW L" created.", childData.dwPid);
		LOGV(L"RegisterNewChildProcess...");
		RegisterNewChildProcess(&childData);
		LOGV(L"RegisterNewChildProcess done.");
		goto after_handling_resp_ok;
	}

	if (MsgIsType(QUERYSTORAGE, pMsg)) {
		REPORTED_CHILD_DATA childData = { 0 };
		LOGV(L"Message is QUERYSTORAGE");
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


DWORD InitProcessBookkeeping(void)
{
	g_tabPerProcess = NULL;
	g_tabFakeIpHostname = NULL;

	if ((g_hDataMutex = CreateMutexW(NULL, FALSE, NULL)) == NULL) return GetLastError();

	return 0;
}
