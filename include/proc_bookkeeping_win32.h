// SPDX-License-Identifier: GPL-2.0-or-later
/* proc_bookkeeping_win32.h
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
#pragma once
#include "defines_win32.h"
#include "hookdll_util_ipc_win32.h"
#include "ut_helpers.h"


/* #define LOCKED(proc) do { \
	DWORD dwWaitResult; \
	DWORD dwErrorCode; \
	DWORD dwReturn = 0; \
	 \
	dwWaitResult = WaitForSingleObject(g_hDataMutex, INFINITE); \
	switch (dwWaitResult) \
	{ \
	case WAIT_OBJECT_0: \
	{ \
		LOGD(L"Mutex fetched."); \
		proc \
	after_proc: \
		if (!ReleaseMutex(g_hDataMutex)) { \
			dwErrorCode = GetLastError(); \
			LOGC(L"Release mutex error: %ls", FormatErrorToStr(dwErrorCode)); \
			exit(dwErrorCode); \
		} \
		LOGD(L"Mutex freed."); \
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
} while(0) */

#pragma pack(push, 1)
typedef struct _IPC_INSTANCE {
	OVERLAPPED oOverlap;
	HANDLE hPipe;

	PXCH_IPC_MSGBUF chReadBuf;
	DWORD cbRead;

	PXCH_IPC_MSGBUF chWriteBuf;
	DWORD cbToWrite;

	DWORD dwState;

	BOOL bPending;

} PXCH_IPC_INSTANCE;


typedef DWORD pid_key_t;
typedef struct _ip_dl_element_t {
	PXCH_IP_ADDRESS Ip;
	struct _ip_dl_element_t* next;
} IpNode;

typedef struct {
	REPORTED_CHILD_DATA Data;
	IpNode* Ips;
	HANDLE hProcess;

	UT_hash_handle hh;
} tab_per_process_t;

typedef struct {
	PXCH_IP_ADDRESS Ip;		// Key
	PXCH_UINT32 dwOptionalPid;	// == 0 if it is fake ip; else == pid

	PXCH_HOSTNAME Hostname;
	PXCH_UINT32 dwTarget;
	PXCH_UINT32 dwResovledIpNum;
	PXCH_IP_ADDRESS ResolvedIps[PXCH_MAX_ARRAY_IP_NUM];

	UT_hash_handle hh;
} tab_fake_ip_hostname_t;
#pragma pack(pop)

extern tab_per_process_t* g_tabPerProcess;
extern tab_fake_ip_hostname_t* g_tabFakeIpHostname;