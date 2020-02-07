#pragma once

#include "defines_generic.h"

#define IPC_STATE_CONNECTING 0
#define IPC_STATE_READING 1
#define IPC_STATE_WRITING 2
#define IPC_INSTANCE_NUM 4
#define IPC_BUFSIZE 4096	// In bytes

#define IPC_MSGDIRECTION_CLIENTTOSERVER 0x80000000
#define IPC_MSGDIRECTION_SERVERTOCLIENT 0x00000000
#define IPC_MSGDIRECTION_MASK 0x80000000

#define IPC_MSGTYPE_MASK (IPC_MSGDIRECTION_MASK - 1)

#define IPC_MSGTYPE_WSTR 0x1

#define IPC_MSGTYPE_HOSTNAMEANDRESOLVEDIP 0x11
#define IPC_MSGTYPE_IPADDRESS 0x12

#define IPC_MSGTYPE_CHILDDATA 0x40
#define IPC_MSGTYPE_QUERYSTORAGE 0x41

#define IPC_MSGTAG_INVALID 0x0

// These are UB. Hope they work well
#define MsgInit(x) *((PXCH_UINT32*)(x)) = 0

#define MsgIsC2S(x) (((*(PXCH_UINT32*)(x)) & IPC_MSGDIRECTION_MASK) == IPC_MSGDIRECTION_CLIENTTOSERVER)
#define MsgIsS2C(x) (((*(PXCH_UINT32*)(x)) & IPC_MSGDIRECTION_MASK) == IPC_MSGDIRECTION_SERVERTOCLIENT)
#define MsgIsType(type, x) (((*(PXCH_UINT32*)(x)) & IPC_MSGTYPE_MASK) == IPC_MSGTYPE_##type)
#define MsgIsInvalid(x) ((*(PXCH_UINT32*)(x)) == IPC_MSGTAG_INVALID)

#define SetMsgC2S(x) *((PXCH_UINT32*)(x)) = (*((PXCH_UINT32*)(x)) & ~IPC_MSGDIRECTION_MASK) | IPC_MSGDIRECTION_CLIENTTOSERVER
#define SetMsgS2C(x) *((PXCH_UINT32*)(x)) = (*((PXCH_UINT32*)(x)) & ~IPC_MSGDIRECTION_MASK) | IPC_MSGDIRECTION_SERVERTOCLIENT
#define SetMsgInvalid(x) (*(PXCH_UINT32*)(x)) = IPC_MSGTAG_INVALID

typedef const char* CIPC_MSGBUF;
typedef char IPC_MSGBUF[IPC_BUFSIZE];
typedef char* PIPC_MSGBUF;
typedef CIPC_MSGBUF PCIPC_MSGBUF;

#pragma pack(push, 1)
typedef struct _IPC_MSGHDR_WSTR {
	PXCH_UINT32 dwTag;
	PXCH_UINT32 cchLength;
} IPC_MSGHDR_WSTR;

typedef struct _IPC_MSGHDR_HOSTNAMEANDRESOLVEDIP {
	PXCH_UINT32 dwTag;
	PXCH_UINT32 dwPid;
	PXCH_HOSTNAME Hostname;
	PXCH_UINT32 dwWillMapResolvedIpToHost;
	PXCH_UINT32 dwResolvedIpNum;
} IPC_MSGHDR_HOSTNAMEANDRESOLVEDIP;

#define IPC_RESOLVEDIP_ARR(pHdrHostnameAndResolvedIp) ((PXCH_IP_ADDRESS*)((char*)(pHdrHostnameAndResolvedIp) + sizeof(IPC_MSGHDR_HOSTNAMEANDRESOLVEDIP)))

typedef struct _IPC_MSGHDR_IPADDRESS {
	PXCH_UINT32 dwTag;
	PXCH_UINT32 dwPid;
	PXCH_IP_ADDRESS Ip;
} IPC_MSGHDR_IPADDRESS;

#pragma pack(pop)

PXCH_UINT32 IpcCommunicateWithServer(const IPC_MSGBUF sendMessage, PXCH_UINT32 cbSendMessageSize, IPC_MSGBUF responseMessage, PXCH_UINT32* pcbResponseMessageSize);

PXCH_UINT32 WstrToMessage(IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, const wchar_t* szWstr);
PXCH_UINT32 MessageToWstr(wchar_t* wstr, CIPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize);

#define MAX_RESOLVED_IP_NUM 10

PXCH_UINT32 HostnameAndResolvedIpToMessage(IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, PXCH_UINT32 dwPid, const PXCH_HOSTNAME* Hostname, BOOL bWillMapResolvedIpToHost, PXCH_UINT32 dwResolvedIpNum, const PXCH_IP_ADDRESS* ResolvedIps);
PXCH_UINT32 MessageToHostnameAndResolvedIp(PXCH_UINT32* pdwPid, PXCH_HOSTNAME* pHostname, BOOL* pbWillMapResolvedIpToHost, PXCH_UINT32* pdwResolvedIpNum, PXCH_IP_ADDRESS* ResolvedIps, CIPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize);

PXCH_UINT32 IpAddressToMessage(IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, PXCH_UINT32 dwPid, const PXCH_IP_ADDRESS* pIp);
PXCH_UINT32 MessageToIpAddress(PXCH_UINT32* pdwPid, PXCH_IP_ADDRESS* pIp, CIPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize);