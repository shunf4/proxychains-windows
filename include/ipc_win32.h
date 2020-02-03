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
} REPORTED_CHILD_DATA;

typedef struct _IPC_MSGHDR_CHILDDATA {
	UINT32 dwTag;
	REPORTED_CHILD_DATA childData;
} IPC_MSGHDR_CHILDDATA;

typedef struct _IPC_MSGHDR_QUERYSTORAGE {
	UINT32 dwTag;
	DWORD dwChildPid;
} IPC_MSGHDR_QUERYSTORAGE;
#pragma pack(pop)

DWORD ChildDataToMessage(IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, const REPORTED_CHILD_DATA* pChildData);
DWORD MessageToChildData(REPORTED_CHILD_DATA* pChildData, CIPC_MSGBUF chMessageBuf, DWORD cbMessageSize);

DWORD QueryStorageToMessage(IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, DWORD dwChildPid);
DWORD MessageToQueryStorage(DWORD* pdwChildPid, CIPC_MSGBUF chMessageBuf, DWORD cbMessageSize);
