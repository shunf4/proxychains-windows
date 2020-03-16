// SPDX-License-Identifier: GPL-2.0-or-later
/* hookdll_util_ipc_generic.h
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

#include "defines_generic.h"

#define PXCH_IPC_STATE_CONNECTING 0
#define PXCH_IPC_STATE_READING 1
#define PXCH_IPC_STATE_WRITING 2
#define PXCH_IPC_INSTANCE_NUM 4
#define PXCH_IPC_BUFSIZE 4096	// In bytes

// #define PXCH_IPC_MSGDIRECTION_CLIENTTOSERVER 0x80000000
// #define PXCH_IPC_MSGDIRECTION_SERVERTOCLIENT 0x00000000
// #define PXCH_IPC_MSGDIRECTION_MASK 0x80000000

#define PXCH_IPC_MSGTYPE_MASK (~0x80000000)

#define PXCH_IPC_MSGTYPE_WSTR 0x1

#define PXCH_IPC_MSGTYPE_HOSTNAMEANDIPS 0x11

#define PXCH_IPC_MSGTYPE_CHILDDATA 0x40
#define PXCH_IPC_MSGTYPE_QUERYSTORAGE 0x41

#define PXCH_IPC_MSGTAG_INVALID 0x0

// These are UB. Hope they work well
#define MsgInit(x) *((PXCH_UINT32*)(x)) = 0

// #define MsgIsC2S(x) (((*(PXCH_UINT32*)(x)) & PXCH_IPC_MSGDIRECTION_MASK) == PXCH_IPC_MSGDIRECTION_CLIENTTOSERVER)
// #define MsgIsS2C(x) (((*(PXCH_UINT32*)(x)) & PXCH_IPC_MSGDIRECTION_MASK) == PXCH_IPC_MSGDIRECTION_SERVERTOCLIENT)
#define MsgIsType(type, x) (((*(PXCH_UINT32*)(x)) & PXCH_IPC_MSGTYPE_MASK) == PXCH_IPC_MSGTYPE_##type)
#define MsgIsInvalid(x) ((*(PXCH_UINT32*)(x)) == PXCH_IPC_MSGTAG_INVALID)

#define SetMsgC2S(x) *((PXCH_UINT32*)(x)) = (*((PXCH_UINT32*)(x)) & ~PXCH_IPC_MSGDIRECTION_MASK) | PXCH_IPC_MSGDIRECTION_CLIENTTOSERVER
#define SetMsgS2C(x) *((PXCH_UINT32*)(x)) = (*((PXCH_UINT32*)(x)) & ~PXCH_IPC_MSGDIRECTION_MASK) | PXCH_IPC_MSGDIRECTION_SERVERTOCLIENT
#define SetMsgInvalid(x) (*(PXCH_UINT32*)(x)) = PXCH_IPC_MSGTAG_INVALID

typedef const char* CPXCH_IPC_MSGBUF;
typedef char PXCH_IPC_MSGBUF[PXCH_IPC_BUFSIZE];
typedef char* PPXCH_IPC_MSGBUF;
typedef CPXCH_IPC_MSGBUF PCPXCH_IPC_MSGBUF;

#pragma pack(push, 1)
typedef struct _IPC_MSGHDR_WSTR {
	PXCH_UINT32 dwTag;
	PXCH_UINT32 cchLength;
} PXCH_IPC_MSGHDR_WSTR;

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
	PXCH_UINT32 dwTarget;
	PXCH_UINT32 dwWillMapResolvedIpToHost;
	PXCH_UINT32 dwIpNum;
} PXCH_IPC_MSGHDR_HOSTNAMEANDIPS;

#define PXCH_IPC_IP_ARR(pHdrHostnameAndIp) ((PXCH_IP_ADDRESS*)((char*)(pHdrHostnameAndIp) + sizeof(PXCH_IPC_MSGHDR_HOSTNAMEANDIPS)))

#pragma pack(pop)

PXCH_UINT32 IpcCommunicateWithServer(const PXCH_IPC_MSGBUF sendMessage, PXCH_UINT32 cbSendMessageSize, PXCH_IPC_MSGBUF responseMessage, PXCH_UINT32* pcbResponseMessageSize);

PXCH_DLL_API PXCH_UINT32 WstrToMessage(PXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, const wchar_t* szWstr);
PXCH_DLL_API PXCH_UINT32 MessageToWstr(wchar_t* wstr, CPXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize);

