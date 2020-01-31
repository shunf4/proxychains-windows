#pragma once

#ifndef __IPC_H__
#define __IPC_H__
#include "stdafx.h"
#include "pxch_defines.h"

#define IPC_STATE_CONNECTING 0
#define IPC_STATE_READING 1
#define IPC_STATE_WRITING 2
#define IPC_INSTANCE_NUM 4
#define IPC_BUFSIZE 4096	// In bytes

typedef const char CIPC_MSGBUF[IPC_BUFSIZE];
typedef char IPC_MSGBUF[IPC_BUFSIZE];

#define IPC_MSGDIRECTION_CLIENTTOSERVER 0x80000000
#define IPC_MSGDIRECTION_SERVERTOCLIENT 0x00000000
#define IPC_MSGDIRECTION_MASK 0x80000000

#define IPC_MSGTYPE_MASK (IPC_MSGDIRECTION_MASK - 1)

#define IPC_MSGTYPE_WSTR 0x1

#define IPC_MSGTYPE_GETHOSTBYFAKEIPV4 0x11
#define IPC_MSGTYPE_GETHOSTBYFAKEIPV6 0x12

#define IPC_MSGTYPE_GETFAKEIPV4BYHOST 0x21
#define IPC_MSGTYPE_GETFAKEIPV6BYHOST 0x22
#define IPC_MSGTYPE_RESPHOST 0x2F

#define IPC_MSGTYPE_RESPIPS 0x30
#define IPC_MSGTYPE_RESPIPV4 0x31
#define IPC_MSGTYPE_RESPIPV6 0x32

#define IPC_MSGTYPE_CHILDDATA 0x40
#define IPC_MSGTYPE_QUERYSTORAGE 0x41

#define IPC_MSGTAG_INVALID 0x0

#define MsgIsC2S(x) (((*(DWORD*)(x)) & IPC_MSGDIRECTION_MASK) == IPC_MSGDIRECTION_CLIENTTOSERVER)
#define MsgIsS2C(x) (((*(DWORD*)(x)) & IPC_MSGDIRECTION_MASK) == IPC_MSGDIRECTION_SERVERTOCLIENT)
#define MsgIsType(type, x) (((*(DWORD*)(x)) & IPC_MSGTYPE_MASK) == IPC_MSGTYPE_##type)
#define MsgIsInvalid(x) ((*(DWORD*)(x)) == IPC_MSGTAG_INVALID)

#define SetMsgC2S(x) *((DWORD*)(x)) = (*((DWORD*)(x)) & ~IPC_MSGDIRECTION_MASK) | IPC_MSGDIRECTION_CLIENTTOSERVER
#define SetMsgS2C(x) *((DWORD*)(x)) = (*((DWORD*)(x)) & ~IPC_MSGDIRECTION_MASK) | IPC_MSGDIRECTION_SERVERTOCLIENT
#define SetMsgInvalid(x) (*(DWORD*)(x)) = IPC_MSGTAG_INVALID

#pragma pack(push, 1)
typedef struct _IPC_MSGHDR_WSTR {
	UINT32 u32Tag;
	UINT32 cchLength;
} IPC_MSGHDR_WSTR;

typedef struct _REPORTED_CHILD_DATA {
	DWORD dwPid;
	PROXYCHAINS_CONFIG* pSavedPxchConfig;
	INJECT_REMOTE_DATA* pSavedRemoteData;
} REPORTED_CHILD_DATA;

typedef struct _IPC_MSGHDR_CHILDDATA {
	UINT32 u32Tag;
	REPORTED_CHILD_DATA childData;
} IPC_MSGHDR_CHILDDATA;

typedef struct _IPC_MSGHDR_QUERYSTORAGE {
	UINT32 u32Tag;
	DWORD dwChildPid;
} IPC_MSGHDR_QUERYSTORAGE;

#pragma pack(pop)

DWORD WstrToMessage(IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, PCWSTR szWstr);
DWORD MessageToWstr(PWSTR wstr, CIPC_MSGBUF chMessageBuf, DWORD cbMessageSize);

DWORD ChildDataToMessage(IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, const REPORTED_CHILD_DATA* pChildData);
DWORD MessageToChildData(REPORTED_CHILD_DATA* pChildData, CIPC_MSGBUF chMessageBuf, DWORD cbMessageSize);

DWORD QueryStorageToMessage(IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, DWORD dwChildPid);
DWORD MessageToQueryStorage(DWORD* pdwChildPid, CIPC_MSGBUF chMessageBuf, DWORD cbMessageSize);

#endif