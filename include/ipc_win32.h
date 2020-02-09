#pragma once

#include "defines_win32.h"
#include "ipc_generic.h"

#pragma pack(push, 1)
typedef struct _REPORTED_CHILD_DATA {
	DWORD dwPid;
	HANDLE hMapFile;
	LPCVOID pMappedBuf;
	PROXYCHAINS_CONFIG* pSavedPxchConfig;
	PXCH_INJECT_REMOTE_DATA* pSavedRemoteData;
	PXCH_UINT32 dwSavedTlsIndex;
	void* /* UT_array* */ pSavedHeapAllocatedPointers;
} REPORTED_CHILD_DATA;

typedef struct _IPC_MSGHDR_CHILDDATA {
	UINT32 dwTag;
	REPORTED_CHILD_DATA ChildData;
} PXCH_IPC_MSGHDR_CHILDDATA;

typedef struct _IPC_MSGHDR_QUERYSTORAGE {
	UINT32 dwTag;
	DWORD dwChildPid;
} PXCH_IPC_MSGHDR_QUERYSTORAGE;
#pragma pack(pop)

DWORD ChildDataToMessage(PXCH_IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, const REPORTED_CHILD_DATA* pChildData);
DWORD MessageToChildData(REPORTED_CHILD_DATA* pChildData, CPXCH_IPC_MSGBUF chMessageBuf, DWORD cbMessageSize);

DWORD QueryStorageToMessage(PXCH_IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, DWORD dwChildPid);
DWORD MessageToQueryStorage(DWORD* pdwChildPid, CPXCH_IPC_MSGBUF chMessageBuf, DWORD cbMessageSize);
