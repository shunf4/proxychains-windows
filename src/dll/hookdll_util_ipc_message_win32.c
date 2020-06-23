// SPDX-License-Identifier: GPL-2.0-or-later
/* hookdll_util_ipc_message_win32.c
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
#include "hookdll_util_ipc_win32.h"

PXCH_DLL_API PXCH_UINT32 WstrToMessage(PXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, const wchar_t* szWstr)
{
	PXCH_IPC_MSGHDR_WSTR* pHdr = (PXCH_IPC_MSGHDR_WSTR*)chMessageBuf;
	PWCHAR szWstrEnd;

	pHdr->dwTag = PXCH_IPC_MSGTYPE_WSTR;
	if (FAILED(StringCchCopyExW((PWSTR)(chMessageBuf + sizeof(PXCH_IPC_MSGHDR_WSTR)), (sizeof(PXCH_IPC_MSGBUF) - sizeof(PXCH_IPC_MSGHDR_WSTR)) / sizeof(WCHAR), szWstr, &szWstrEnd, NULL, 0))) goto err_copy;
	pHdr->cchLength = (PXCH_UINT32)(((char*)szWstrEnd - (chMessageBuf + sizeof(PXCH_IPC_MSGHDR_WSTR))) / sizeof(WCHAR));
	*pcbMessageSize = (PXCH_UINT32)((char*)szWstrEnd - chMessageBuf);
	return 0;

err_copy:
	pHdr->cchLength = 0;
	*pcbMessageSize = sizeof(PXCH_IPC_MSGHDR_WSTR);
	return ERROR_FUNCTION_FAILED;
}


PXCH_DLL_API PXCH_UINT32 MessageToWstr(wchar_t* szWstr, CPXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize)
{
	const PXCH_IPC_MSGHDR_WSTR* pHdr = (const PXCH_IPC_MSGHDR_WSTR*)chMessageBuf;
	szWstr[0] = L'\0';
	if (!MsgIsType(WSTR, chMessageBuf)) return ERROR_INVALID_PARAMETER;
	if (pHdr->cchLength * sizeof(WCHAR) + sizeof(PXCH_IPC_MSGHDR_WSTR) > sizeof(PXCH_IPC_MSGBUF)) return ERROR_INSUFFICIENT_BUFFER;
	if (FAILED(StringCchCopyNW(szWstr, PXCH_IPC_BUFSIZE / sizeof(WCHAR), (PCWCH)(chMessageBuf + sizeof(PXCH_IPC_MSGHDR_WSTR)), pHdr->cchLength))) return ERROR_FUNCTION_FAILED;
	return 0;
}


PXCH_DLL_API PXCH_UINT32 ChildDataToMessage(PXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, const PXCH_CHILD_DATA* pChildData)
{
	PXCH_IPC_MSGHDR_CHILDDATA* pHdr = (PXCH_IPC_MSGHDR_CHILDDATA*)chMessageBuf;

	pHdr->dwTag = PXCH_IPC_MSGTYPE_CHILDDATA;
	CopyMemory(&pHdr->ChildData, pChildData, sizeof(PXCH_CHILD_DATA));
	*pcbMessageSize = sizeof(PXCH_IPC_MSGHDR_CHILDDATA);
	return 0;
}


PXCH_DLL_API PXCH_UINT32 MessageToChildData(PXCH_CHILD_DATA* pChildData, CPXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize)
{
	const PXCH_IPC_MSGHDR_CHILDDATA* pHdr = (const PXCH_IPC_MSGHDR_CHILDDATA*)chMessageBuf;
	if (!MsgIsType(CHILDDATA, chMessageBuf)) return ERROR_INVALID_PARAMETER;
	if (pChildData) CopyMemory(pChildData, &pHdr->ChildData, sizeof(PXCH_CHILD_DATA));
	return 0;
}


PXCH_DLL_API PXCH_UINT32 QueryStorageToMessage(PXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, PXCH_UINT32 dwChildPid)
{
	PXCH_IPC_MSGHDR_QUERYSTORAGE* pHdr = (PXCH_IPC_MSGHDR_QUERYSTORAGE*)chMessageBuf;

	pHdr->dwTag = PXCH_IPC_MSGTYPE_QUERYSTORAGE;
	pHdr->dwChildPid = dwChildPid;
	*pcbMessageSize = sizeof(PXCH_IPC_MSGHDR_QUERYSTORAGE);
	return 0;
}


PXCH_DLL_API PXCH_UINT32 MessageToQueryStorage(PXCH_UINT32* pdwChildPid, CPXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize)
{
	const PXCH_IPC_MSGHDR_QUERYSTORAGE* pHdr = (const PXCH_IPC_MSGHDR_QUERYSTORAGE*)chMessageBuf;
	if (!MsgIsType(QUERYSTORAGE, chMessageBuf)) return ERROR_INVALID_PARAMETER;
	if (pdwChildPid) *pdwChildPid = pHdr->dwChildPid;
	return 0;
}


PXCH_DLL_API PXCH_UINT32 HostnameAndIpsToMessage(PXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, PXCH_UINT32 dwPid, const PXCH_HOSTNAME* Hostname, BOOL bWillMapResolvedIpToHost, PXCH_UINT32 dwIpNum, const PXCH_IP_ADDRESS* Ips, PXCH_UINT32 dwTarget)
{
	PXCH_IPC_MSGHDR_HOSTNAMEANDIPS* pHdr = (PXCH_IPC_MSGHDR_HOSTNAMEANDIPS*)chMessageBuf;

	pHdr->dwTag = PXCH_IPC_MSGTYPE_HOSTNAMEANDIPS;
	pHdr->dwIpNum = dwIpNum;
	pHdr->dwWillMapResolvedIpToHost = bWillMapResolvedIpToHost;
	pHdr->Hostname = *Hostname;
	pHdr->dwPid = dwPid;
	pHdr->dwTarget = dwTarget;

	CopyMemory((char*)chMessageBuf + sizeof(PXCH_IPC_MSGHDR_HOSTNAMEANDIPS), Ips, sizeof(PXCH_IP_ADDRESS) * dwIpNum);
	*pcbMessageSize = sizeof(PXCH_IPC_MSGHDR_HOSTNAMEANDIPS) + sizeof(PXCH_IP_ADDRESS) * dwIpNum;
	return 0;
}


PXCH_DLL_API PXCH_UINT32 MessageToHostnameAndIps(PXCH_UINT32* pdwPid, PXCH_HOSTNAME* pHostname, BOOL* pbWillMapResolvedIpToHost, PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, PXCH_UINT32* pdwTarget, CPXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize)
{
	const PXCH_IPC_MSGHDR_HOSTNAMEANDIPS* pHdr = (const PXCH_IPC_MSGHDR_HOSTNAMEANDIPS*)chMessageBuf;
	if (!MsgIsType(HOSTNAMEANDIPS, chMessageBuf)) return ERROR_INVALID_PARAMETER;

	if (pHostname) *pHostname = pHdr->Hostname;
	if (pbWillMapResolvedIpToHost) *pbWillMapResolvedIpToHost = pHdr->dwWillMapResolvedIpToHost;
	if (pdwIpNum) *pdwIpNum = pHdr->dwIpNum;
	if (pdwPid) *pdwPid = pHdr->dwPid;
	if (pdwTarget) *pdwTarget = pHdr->dwTarget;
	
	if (Ips) CopyMemory(Ips, (const char*)chMessageBuf + sizeof(PXCH_IPC_MSGHDR_HOSTNAMEANDIPS), sizeof(PXCH_IP_ADDRESS) * pHdr->dwIpNum);
	return 0;
}
