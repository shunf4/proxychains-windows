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

#define IPC_MSGTYPE_HOSTNAMEANDIPS 0x11

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

typedef struct _IPC_MSGHDR_HOSTNAMEANDIPS {
	PXCH_UINT32 dwTag;
	PXCH_UINT32 dwPid;
	// Hostname meaning:
	// C2S:
	//   wTag == HOSTNAME && szValue[0] != L'\0' :
	//     Client registers hostname, retreiving fake ips;
    //   else: Client retrieves hostname provided fake ip/resolved ip.
	// S2C:
	//   wTag == HOSTNAME && szValue[0] != L'\0' :
	//     Server can't find fake ip/resolved ip provided by client, returning it as-is;
	//   else: Server returns hostname and resolved ips corresponding to fake ip/resolved ip provided by client.
	PXCH_HOSTNAME Hostname;
	PXCH_UINT32 dwWillProxy;
	PXCH_UINT32 dwWillMapResolvedIpToHost;
	PXCH_UINT32 dwIpNum;
} IPC_MSGHDR_HOSTNAMEANDIPS;

#define IPC_IP_ARR(pHdrHostnameAndIp) ((PXCH_IP_ADDRESS*)((char*)(pHdrHostnameAndIp) + sizeof(IPC_MSGHDR_HOSTNAMEANDIPS)))

#pragma pack(pop)

PXCH_UINT32 IpcCommunicateWithServer(const IPC_MSGBUF sendMessage, PXCH_UINT32 cbSendMessageSize, IPC_MSGBUF responseMessage, PXCH_UINT32* pcbResponseMessageSize);

PXCH_UINT32 WstrToMessage(IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, const wchar_t* szWstr);
PXCH_UINT32 MessageToWstr(wchar_t* wstr, CIPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize);

PXCH_UINT32 HostnameAndIpsToMessage(IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, PXCH_UINT32 dwPid, const PXCH_HOSTNAME* Hostname, BOOL bWillMapResolvedIpToHost, PXCH_UINT32 dwIpNum, const PXCH_IP_ADDRESS* Ips, BOOL bWillProxy);
PXCH_UINT32 MessageToHostnameAndIps(PXCH_UINT32* pdwPid, PXCH_HOSTNAME* pHostname, BOOL* pbWillMapResolvedIpToHost, PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, BOOL* pbWillProxy, CIPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize);
