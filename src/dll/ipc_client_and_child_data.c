#include "defines_win32.h"
#include "log_win32.h"
#include "hookdll_win32.h"
#include "hookdll_interior_win32.h"


PXCH_UINT32 IpcCommunicateWithServer(const PXCH_IPC_MSGBUF sendMessage, PXCH_UINT32 cbSendMessageSize, PXCH_IPC_MSGBUF responseMessage, PXCH_UINT32* pcbResponseMessageSize)
{
	HANDLE hPipe;
	DWORD cbToWrite;
	DWORD cbWritten;
	DWORD dwMode;
	DWORD dwErrorCode;
	BOOL bReturn;

	if (!g_pPxchConfig) return ERROR_INVALID_STATE;

	*pcbResponseMessageSize = 0;
	SetMsgInvalid(responseMessage);

	ODBGSTRLOG(L"before createfile");

	// Try to open a named pipe; wait for it if necessary
	while (1)
	{
		hPipe = CreateFileW(g_pPxchConfig->szIpcPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE) break;
		if ((dwErrorCode = GetLastError()) != ERROR_PIPE_BUSY) goto err_open_pipe;

		// Wait needed
		if (!WaitNamedPipeW(g_pPxchConfig->szIpcPipeName, 2000)) goto err_wait_pipe;
	}

	ODBGSTRLOG(L"after createfile");

	dwMode = PIPE_READMODE_MESSAGE;
	bReturn = SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
	if (!bReturn) goto err_set_handle_state;

	ODBGSTRLOG(L"after SetNamedPipeHandleState");

	// Request
	cbToWrite = (DWORD)cbSendMessageSize;
	bReturn = WriteFile(hPipe, sendMessage, cbToWrite, &cbWritten, NULL);
	if (!bReturn || cbToWrite != cbWritten) goto err_write;

	ODBGSTRLOG(L"after WriteFile");

	// Read response
	bReturn = ReadFile(hPipe, responseMessage, PXCH_IPC_BUFSIZE, pcbResponseMessageSize, NULL);
	if (!bReturn) goto err_read;

	ODBGSTRLOG(L"after ReadFile");

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
	/*REPORTED_CHILD_DATA ChildData;
	PXCH_IPC_MSGBUF chMessageBuf;
	PXCH_IPC_MSGBUF chRespMessageBuf;
	DWORD cbMessageSize;
	DWORD cbRespMessageSize;
	DWORD dwErrorCode;

	ChildData.dwPid = GetCurrentProcessId();
	ChildData.pSavedPxchConfig = g_pPxchConfig;
	ChildData.pSavedRemoteData = g_pRemoteData;

	if ((dwErrorCode = ChildDataToMessage(chMessageBuf, &cbMessageSize, &ChildData)) != NO_ERROR) return dwErrorCode;
	if ((dwErrorCode = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, &cbRespMessageSize)) != NO_ERROR) return dwErrorCode;

	return 0;*/

	DWORD dwErrorCode;

	HANDLE hMapFile;
	WCHAR szFileMappingName[MAX_FILEMAPPING_BUFSIZE];
	REPORTED_CHILD_DATA* pChildData;
	DWORD dwCurrentProcessId;

	PXCH_IPC_MSGBUF chMessageBuf;
	PXCH_IPC_MSGBUF chRespMessageBuf;
	DWORD cbMessageSize;
	DWORD cbRespMessageSize;

	dwCurrentProcessId = GetCurrentProcessId();

	if (FAILED(StringCchPrintfW(szFileMappingName, _countof(szFileMappingName), L"%ls" WPRDW, g_szChildDataSavingFileMappingPrefix, dwCurrentProcessId))) goto err_sprintf;
	hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(REPORTED_CHILD_DATA), szFileMappingName);
	if (hMapFile == NULL) goto err_filemapping;

	pChildData = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(REPORTED_CHILD_DATA));
	if (pChildData == NULL) goto err_mapviewoffile;

	pChildData->dwPid = dwCurrentProcessId;
	pChildData->hMapFile = hMapFile;
	pChildData->pMappedBuf = pChildData;
	pChildData->pSavedPxchConfig = g_pPxchConfig;
	pChildData->pSavedRemoteData = g_pRemoteData;
	pChildData->dwSavedTlsIndex = g_dwTlsIndex;
	pChildData->pSavedHeapAllocatedPointers = g_arrHeapAllocatedPointers;

	if ((dwErrorCode = ChildDataToMessage(chMessageBuf, &cbMessageSize, pChildData)) != NO_ERROR) return dwErrorCode;
	if ((dwErrorCode = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, &cbRespMessageSize)) != NO_ERROR) return dwErrorCode;

	IPCLOGV(L"Saved child data, g_pPxchConfig = %p", g_pPxchConfig);

	return 0;

err_sprintf:
	IPCLOGE(L"StringCchPrintfW failed");
	return ERROR_INVALID_DATA;

err_filemapping:
	dwErrorCode = GetLastError();
	IPCLOGE(L"CreateFileMappingW failed: %ls", FormatErrorToStr(dwErrorCode));
	return dwErrorCode;

err_mapviewoffile:
	dwErrorCode = GetLastError();
	IPCLOGE(L"MapViewOfFile failed");
	CloseHandle(hMapFile);
	return dwErrorCode;
}


PXCH_UINT32 RestoreChildData()
{
	// Restore child process essential data overwritten by Cygwin fork().

	/*REPORTED_CHILD_DATA ChildData;
	PXCH_IPC_MSGBUF chMessageBuf;
	PXCH_IPC_MSGBUF chRespMessageBuf;
	DWORD cbMessageSize;
	DWORD cbRespMessageSize;
	
	ChildData.dwPid = GetCurrentProcessId();

	if (ChildData.dwPid == g_pPxchConfig->dwMasterProcessId) return 0;

	if ((dwErrorCode = QueryStorageToMessage(chMessageBuf, &cbMessageSize, ChildData.dwPid)) != NO_ERROR) return dwErrorCode;
	if ((dwErrorCode = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, &cbRespMessageSize)) != NO_ERROR) return dwErrorCode;
	if ((dwErrorCode = MessageToChildData(&ChildData, chRespMessageBuf, cbRespMessageSize)) != NO_ERROR) return dwErrorCode;*/

	PXCH_UINT32 dwErrorCode;

	HANDLE hMapFile;
	HANDLE hMapFileWhenCreated;
	LPCVOID pMappedBufWhenCreated;
	WCHAR szFileMappingName[MAX_FILEMAPPING_BUFSIZE];
	REPORTED_CHILD_DATA* pChildData;
	DWORD dwRealCurrentProcessId;

	if ((dwRealCurrentProcessId = GetCurrentProcessId()) == g_dwCurrentProcessIdForVerify) return 0;

	// Overwritten, now restoring
	g_pPxchConfig = NULL;
	g_pRemoteData = NULL;

	if (FAILED(StringCchPrintfW(szFileMappingName, _countof(szFileMappingName), L"%ls" WPRDW, g_szChildDataSavingFileMappingPrefix, dwRealCurrentProcessId))) goto err_sprintf;
	// hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READONLY, 0, sizeof(REPORTED_CHILD_DATA), szFileMappingName);
	hMapFile = OpenFileMappingW(FILE_MAP_READ, FALSE, szFileMappingName);
	if (hMapFile == NULL) goto err_filemapping;

	pChildData = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, sizeof(REPORTED_CHILD_DATA));
	if (pChildData == NULL) goto err_mapviewoffile;

	if (pChildData->dwPid != dwRealCurrentProcessId || pChildData->pSavedPxchConfig == NULL || pChildData->pSavedRemoteData == NULL) goto err_data_invalid;
	g_pPxchConfig = pChildData->pSavedPxchConfig;
	g_pRemoteData = pChildData->pSavedRemoteData;
	g_dwTlsIndex = pChildData->dwSavedTlsIndex;
	g_arrHeapAllocatedPointers = pChildData->pSavedHeapAllocatedPointers;
	hMapFileWhenCreated = pChildData->hMapFile;
	g_dwCurrentProcessIdForVerify = pChildData->dwPid;
	pMappedBufWhenCreated = pChildData->pMappedBuf;

	IPCLOGV(L"g_pPxchConfig restored to %p", g_pPxchConfig);
	IPCLOGV(L"g_pRemoteData restored to %p", g_pRemoteData);
	IPCLOGV(L"g_arrHeapAllocatedPointers restored to %p", g_arrHeapAllocatedPointers);

	UnmapViewOfFile(pChildData);
	UnmapViewOfFile(pMappedBufWhenCreated);
	CloseHandle(hMapFile);
	CloseHandle(hMapFileWhenCreated);
	
	return 0;

err_data_invalid:
	IPCLOGE(L"Saved CHILDDATA invalid");
	ODBGSTRLOG(L"Saved CHILDDATA invalid");
	return ERROR_INVALID_DATA;

err_sprintf:
	// Won't log because g_pPxchConfig == NULL. Same as below
	IPCLOGE(L"StringCchPrintfW failed");
	return ERROR_INVALID_DATA;

err_filemapping:
	dwErrorCode = GetLastError();
	ODBGSTRLOG(L"OpenFileMappingW failed: %ls", FormatErrorToStr(dwErrorCode));
	IPCLOGE(L"OpenFileMappingW failed");
	return dwErrorCode;

err_mapviewoffile:
	dwErrorCode = GetLastError();
	ODBGSTRLOG(L"MapViewOfFile failed: %ls", FormatErrorToStr(dwErrorCode));
	IPCLOGE(L"MapViewOfFile failed");
	CloseHandle(hMapFile);
	return dwErrorCode;
}
