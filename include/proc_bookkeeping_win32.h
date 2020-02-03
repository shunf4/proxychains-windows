#pragma once
#include "defines_win32.h"
#include "ipc_win32.h"
#include "uthash.h"


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


typedef DWORD pid_key_t;
typedef struct _ip_dl_element_t {
	PXCH_IP_ADDRESS ip;
	struct _ip_dl_element_t* prev;
	struct _ip_dl_element_t* next;
} ip_dl_element_t;

typedef struct {
	REPORTED_CHILD_DATA data;
	ip_dl_element_t* fakeIps;

	UT_hash_handle hh;
} tab_per_process_t;

typedef struct {
	PXCH_IP_ADDRESS ip;	// Key
	WCHAR szHostname[MAX_HOSTNAME_BUFSIZE];

	UT_hash_handle hh;
} tab_fake_ip_hostname_t;


extern tab_per_process_t* g_tabPerProcess;
extern HANDLE g_hDataMutex;
extern tab_fake_ip_hostname_t* g_tabFakeIpHostname;