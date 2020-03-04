// SPDX-License-Identifier: GPL-2.0-or-later
/* ipc_client_and_child_data.c
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
#include "defines_win32.h"
#include "log_win32.h"
#include "hookdll_util_win32.h"
#include "hookdll_win32.h"

BOOL g_bSystemInfoInitialized;
SYSTEM_INFO g_SystemInfo;

PXCH_UINT32 IpcCommunicateWithServer(const PXCH_IPC_MSGBUF sendMessage, PXCH_UINT32 cbSendMessageSize, PXCH_IPC_MSGBUF responseMessage, PXCH_UINT32* pcbResponseMessageSize)
{
	HANDLE hPipe;
	DWORD cbToWrite;
	DWORD cbWritten;
	DWORD dwMode;
	DWORD dwLastError;
	BOOL bReturn;

	if (!g_pPxchConfig) return ERROR_INVALID_STATE;

	*pcbResponseMessageSize = 0;
	SetMsgInvalid(responseMessage);

	ODBGSTRLOGV(L"before createfile");

	// Try to open a named pipe; wait for it if necessary
	while (1)
	{
		hPipe = CreateFileW(g_pPxchConfig->szIpcPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE) break;
		if ((dwLastError = GetLastError()) != ERROR_PIPE_BUSY) goto err_open_pipe;

		// Wait needed
		if (!WaitNamedPipeW(g_pPxchConfig->szIpcPipeName, 2000)) goto err_wait_pipe;
	}

	ODBGSTRLOGV(L"after createfile");

	dwMode = PIPE_READMODE_MESSAGE;
	bReturn = SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
	if (!bReturn) goto err_set_handle_state;

	ODBGSTRLOGV(L"after SetNamedPipeHandleState");

	// Request
	cbToWrite = (DWORD)cbSendMessageSize;
	bReturn = WriteFile(hPipe, sendMessage, cbToWrite, &cbWritten, NULL);
	if (!bReturn || cbToWrite != cbWritten) goto err_write;

	ODBGSTRLOGV(L"after WriteFile");

	// Read response
	bReturn = ReadFile(hPipe, responseMessage, PXCH_IPC_BUFSIZE, pcbResponseMessageSize, NULL);
	if (!bReturn) goto err_read;

	ODBGSTRLOGV(L"after ReadFile");

	CloseHandle(hPipe);
	return 0;

err_open_pipe:
	// Opening pipe using CreateFileW error
	return dwLastError;

err_wait_pipe:
	dwLastError = GetLastError();
	// Waiting pipe using WaitNamedPipeW error
	goto close_ret;

err_set_handle_state:
	dwLastError = GetLastError();
	// SetNamedPipeHandleState() error
	goto close_ret;

err_write:
	dwLastError = GetLastError();
	// WriteFile() error
	dwLastError = (dwLastError == NO_ERROR ? ERROR_WRITE_FAULT : dwLastError);
	goto close_ret;

err_read:
	dwLastError = GetLastError();
	// ReadFile() error
	goto close_ret;

close_ret:
	CloseHandle(hPipe);
	return dwLastError;
}


DWORD IpcClientRegisterChildProcess()
{
	/*REPORTED_CHILD_DATA ChildData;
	PXCH_IPC_MSGBUF chMessageBuf;
	PXCH_IPC_MSGBUF chRespMessageBuf;
	DWORD cbMessageSize;
	DWORD cbRespMessageSize;
	DWORD dwLastError;

	ChildData.dwPid = GetCurrentProcessId();
	ChildData.pSavedPxchConfig = g_pPxchConfig;
	ChildData.pSavedRemoteData = g_pRemoteData;

	if ((dwLastError = ChildDataToMessage(chMessageBuf, &cbMessageSize, &ChildData)) != NO_ERROR) return dwLastError;
	if ((dwLastError = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, &cbRespMessageSize)) != NO_ERROR) return dwLastError;

	return 0;*/

	DWORD dwLastError;

	HANDLE hMapFile;
	WCHAR szFileMappingName[PXCH_MAX_FILEMAPPING_BUFSIZE];
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

	if ((dwLastError = ChildDataToMessage(chMessageBuf, &cbMessageSize, pChildData)) != NO_ERROR) return dwLastError;
	if ((dwLastError = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, &cbRespMessageSize)) != NO_ERROR) return dwLastError;

	IPCLOGV(L"Saved child data, g_pPxchConfig = %p", g_pPxchConfig);

	return 0;

err_sprintf:
	IPCLOGE(L"StringCchPrintfW failed");
	return ERROR_INVALID_DATA;

err_filemapping:
	dwLastError = GetLastError();
	IPCLOGE(L"CreateFileMappingW failed: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;

err_mapviewoffile:
	dwLastError = GetLastError();
	IPCLOGE(L"MapViewOfFile failed");
	CloseHandle(hMapFile);
	return dwLastError;
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

	if ((dwLastError = QueryStorageToMessage(chMessageBuf, &cbMessageSize, ChildData.dwPid)) != NO_ERROR) return dwLastError;
	if ((dwLastError = IpcCommunicateWithServer(chMessageBuf, cbMessageSize, chRespMessageBuf, &cbRespMessageSize)) != NO_ERROR) return dwLastError;
	if ((dwLastError = MessageToChildData(&ChildData, chRespMessageBuf, cbRespMessageSize)) != NO_ERROR) return dwLastError;*/

	PXCH_UINT32 dwLastError;

	HANDLE hMapFile;
	HANDLE hMapFileWhenCreated;
	LPCVOID pMappedBufWhenCreated;
	WCHAR szFileMappingName[PXCH_MAX_FILEMAPPING_BUFSIZE];
	REPORTED_CHILD_DATA* pChildData;
	DWORD dwRealCurrentProcessId;

	if ((dwRealCurrentProcessId = GetCurrentProcessId()) == g_dwCurrentProcessIdForVerify) return 0;

	ODBGSTRLOGD_FORCE_WITH_EARLY_BUF(L"winpid " WPRDW L" data was rewritten, now restoring", dwRealCurrentProcessId);

	// Overwritten, now restoring
	g_pPxchConfig = NULL;
	g_pRemoteData = NULL;
	g_bSystemInfoInitialized = FALSE;

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
	ODBGSTRLOGD(L"Saved CHILDDATA invalid");
	return ERROR_INVALID_DATA;

err_sprintf:
	// Won't log because g_pPxchConfig == NULL. Same as below
	IPCLOGE(L"StringCchPrintfW failed");
	return ERROR_INVALID_DATA;

err_filemapping:
	dwLastError = GetLastError();
	ODBGSTRLOGD(L"OpenFileMappingW failed: %ls", FormatErrorToStr(dwLastError));
	IPCLOGE(L"OpenFileMappingW failed");
	return dwLastError;

err_mapviewoffile:
	dwLastError = GetLastError();
	ODBGSTRLOGD(L"MapViewOfFile failed: %ls", FormatErrorToStr(dwLastError));
	IPCLOGE(L"MapViewOfFile failed");
	CloseHandle(hMapFile);
	return dwLastError;
}
