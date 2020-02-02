#include "ipc_win32.h"

PXCH_UINT32 WstrToMessage(IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, const wchar_t* szWstr)
{
	IPC_MSGHDR_WSTR* pHdr = (IPC_MSGHDR_WSTR*)chMessageBuf;
	PWCHAR szWstrEnd;

	pHdr->u32Tag = IPC_MSGTYPE_WSTR;
	if (FAILED(StringCchCopyExW((PWSTR)(chMessageBuf + sizeof(IPC_MSGHDR_WSTR)), (sizeof(IPC_MSGBUF) - sizeof(IPC_MSGHDR_WSTR)) / sizeof(WCHAR), szWstr, &szWstrEnd, NULL, 0))) goto err_copy;
	pHdr->cchLength = (DWORD)(((char*)szWstrEnd - (chMessageBuf + sizeof(IPC_MSGHDR_WSTR))) / sizeof(WCHAR));
	*pcbMessageSize = (DWORD)((char*)szWstrEnd - chMessageBuf);
	return 0;

err_copy:
	pHdr->cchLength = 0;
	*pcbMessageSize = sizeof(IPC_MSGHDR_WSTR);
	return ERROR_FUNCTION_FAILED;
}


PXCH_UINT32 MessageToWstr(wchar_t* szWstr, CIPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize)
{
	const IPC_MSGHDR_WSTR* pHdr = (const IPC_MSGHDR_WSTR*)chMessageBuf;
	szWstr[0] = L'\0';
	if (!MsgIsType(WSTR, chMessageBuf)) return ERROR_INVALID_PARAMETER;
	if (pHdr->cchLength * sizeof(WCHAR) + sizeof(IPC_MSGHDR_WSTR) > sizeof(IPC_MSGBUF)) return ERROR_INSUFFICIENT_BUFFER;
	if (FAILED(StringCchCopyNW(szWstr, IPC_BUFSIZE / sizeof(WCHAR), (PCWCH)(chMessageBuf + sizeof(IPC_MSGHDR_WSTR)), pHdr->cchLength))) return ERROR_FUNCTION_FAILED;
	return 0;
}

DWORD ChildDataToMessage(IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, const REPORTED_CHILD_DATA* pChildData)
{
	IPC_MSGHDR_CHILDDATA* pHdr = (IPC_MSGHDR_CHILDDATA*)chMessageBuf;

	pHdr->u32Tag = IPC_MSGTYPE_CHILDDATA;
	CopyMemory(&pHdr->childData, pChildData, sizeof(REPORTED_CHILD_DATA));
	*pcbMessageSize = sizeof(IPC_MSGHDR_CHILDDATA);
	return 0;
}

DWORD MessageToChildData(REPORTED_CHILD_DATA* pChildData, CIPC_MSGBUF chMessageBuf, DWORD cbMessageSize)
{
	const IPC_MSGHDR_CHILDDATA* pHdr = (const IPC_MSGHDR_CHILDDATA*)chMessageBuf;
	if (!MsgIsType(CHILDDATA, chMessageBuf)) return ERROR_INVALID_PARAMETER;
	CopyMemory(pChildData, &pHdr->childData, sizeof(REPORTED_CHILD_DATA));
	return 0;
}

DWORD QueryStorageToMessage(IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, DWORD dwChildPid)
{
	IPC_MSGHDR_QUERYSTORAGE* pHdr = (IPC_MSGHDR_QUERYSTORAGE*)chMessageBuf;

	pHdr->u32Tag = IPC_MSGTYPE_QUERYSTORAGE;
	pHdr->dwChildPid = dwChildPid;
	*pcbMessageSize = sizeof(IPC_MSGHDR_QUERYSTORAGE);
	return 0;
}

DWORD MessageToQueryStorage(DWORD* pdwChildPid, CIPC_MSGBUF chMessageBuf, DWORD cbMessageSize)
{
	const IPC_MSGHDR_QUERYSTORAGE* pHdr = (const IPC_MSGHDR_QUERYSTORAGE*)chMessageBuf;
	if (!MsgIsType(QUERYSTORAGE, chMessageBuf)) return ERROR_INVALID_PARAMETER;
	*pdwChildPid = pHdr->dwChildPid;
	return 0;
}