#include "ipc_win32.h"

PXCH_UINT32 WstrToMessage(PXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, const wchar_t* szWstr)
{
	PXCH_IPC_MSGHDR_WSTR* pHdr = (PXCH_IPC_MSGHDR_WSTR*)chMessageBuf;
	PWCHAR szWstrEnd;

	pHdr->dwTag = PXCH_IPC_MSGTYPE_WSTR;
	if (FAILED(StringCchCopyExW((PWSTR)(chMessageBuf + sizeof(PXCH_IPC_MSGHDR_WSTR)), (sizeof(PXCH_IPC_MSGBUF) - sizeof(PXCH_IPC_MSGHDR_WSTR)) / sizeof(WCHAR), szWstr, &szWstrEnd, NULL, 0))) goto err_copy;
	pHdr->cchLength = (DWORD)(((char*)szWstrEnd - (chMessageBuf + sizeof(PXCH_IPC_MSGHDR_WSTR))) / sizeof(WCHAR));
	*pcbMessageSize = (DWORD)((char*)szWstrEnd - chMessageBuf);
	return 0;

err_copy:
	pHdr->cchLength = 0;
	*pcbMessageSize = sizeof(PXCH_IPC_MSGHDR_WSTR);
	return ERROR_FUNCTION_FAILED;
}

PXCH_UINT32 MessageToWstr(wchar_t* szWstr, CPXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize)
{
	const PXCH_IPC_MSGHDR_WSTR* pHdr = (const PXCH_IPC_MSGHDR_WSTR*)chMessageBuf;
	szWstr[0] = L'\0';
	if (!MsgIsType(WSTR, chMessageBuf)) return ERROR_INVALID_PARAMETER;
	if (pHdr->cchLength * sizeof(WCHAR) + sizeof(PXCH_IPC_MSGHDR_WSTR) > sizeof(PXCH_IPC_MSGBUF)) return ERROR_INSUFFICIENT_BUFFER;
	if (FAILED(StringCchCopyNW(szWstr, PXCH_IPC_BUFSIZE / sizeof(WCHAR), (PCWCH)(chMessageBuf + sizeof(PXCH_IPC_MSGHDR_WSTR)), pHdr->cchLength))) return ERROR_FUNCTION_FAILED;
	return 0;
}

DWORD ChildDataToMessage(PXCH_IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, const REPORTED_CHILD_DATA* pChildData)
{
	PXCH_IPC_MSGHDR_CHILDDATA* pHdr = (PXCH_IPC_MSGHDR_CHILDDATA*)chMessageBuf;

	pHdr->dwTag = PXCH_IPC_MSGTYPE_CHILDDATA;
	CopyMemory(&pHdr->ChildData, pChildData, sizeof(REPORTED_CHILD_DATA));
	*pcbMessageSize = sizeof(PXCH_IPC_MSGHDR_CHILDDATA);
	return 0;
}

DWORD MessageToChildData(REPORTED_CHILD_DATA* pChildData, CPXCH_IPC_MSGBUF chMessageBuf, DWORD cbMessageSize)
{
	const PXCH_IPC_MSGHDR_CHILDDATA* pHdr = (const PXCH_IPC_MSGHDR_CHILDDATA*)chMessageBuf;
	if (!MsgIsType(CHILDDATA, chMessageBuf)) return ERROR_INVALID_PARAMETER;
	if (pChildData) CopyMemory(pChildData, &pHdr->ChildData, sizeof(REPORTED_CHILD_DATA));
	return 0;
}

DWORD QueryStorageToMessage(PXCH_IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, DWORD dwChildPid)
{
	PXCH_IPC_MSGHDR_QUERYSTORAGE* pHdr = (PXCH_IPC_MSGHDR_QUERYSTORAGE*)chMessageBuf;

	pHdr->dwTag = PXCH_IPC_MSGTYPE_QUERYSTORAGE;
	pHdr->dwChildPid = dwChildPid;
	*pcbMessageSize = sizeof(PXCH_IPC_MSGHDR_QUERYSTORAGE);
	return 0;
}

DWORD MessageToQueryStorage(DWORD* pdwChildPid, CPXCH_IPC_MSGBUF chMessageBuf, DWORD cbMessageSize)
{
	const PXCH_IPC_MSGHDR_QUERYSTORAGE* pHdr = (const PXCH_IPC_MSGHDR_QUERYSTORAGE*)chMessageBuf;
	if (!MsgIsType(QUERYSTORAGE, chMessageBuf)) return ERROR_INVALID_PARAMETER;
	if (pdwChildPid) *pdwChildPid = pHdr->dwChildPid;
	return 0;
}

PXCH_UINT32 HostnameAndIpsToMessage(PXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, PXCH_UINT32 dwPid, const PXCH_HOSTNAME* Hostname, BOOL bWillMapResolvedIpToHost, PXCH_UINT32 dwIpNum, const PXCH_IP_ADDRESS* Ips, BOOL bWillProxy)
{
	PXCH_IPC_MSGHDR_HOSTNAMEANDIPS* pHdr = (PXCH_IPC_MSGHDR_HOSTNAMEANDIPS*)chMessageBuf;

	pHdr->dwTag = PXCH_IPC_MSGTYPE_HOSTNAMEANDIPS;
	pHdr->dwIpNum = dwIpNum;
	pHdr->dwWillMapResolvedIpToHost = bWillMapResolvedIpToHost;
	pHdr->Hostname = *Hostname;
	pHdr->dwPid = dwPid;
	pHdr->dwWillProxy = bWillProxy;

	CopyMemory((char*)chMessageBuf + sizeof(PXCH_IPC_MSGHDR_HOSTNAMEANDIPS), Ips, sizeof(PXCH_IP_ADDRESS) * dwIpNum);
	*pcbMessageSize = sizeof(PXCH_IPC_MSGHDR_HOSTNAMEANDIPS) + sizeof(PXCH_IP_ADDRESS) * dwIpNum;
	return 0;
}

PXCH_UINT32 MessageToHostnameAndIps(PXCH_UINT32* pdwPid, PXCH_HOSTNAME* pHostname, BOOL* pbWillMapResolvedIpToHost, PXCH_UINT32* pdwIpNum, PXCH_IP_ADDRESS* Ips, BOOL* pbWillProxy, CPXCH_IPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize)
{
	const PXCH_IPC_MSGHDR_HOSTNAMEANDIPS* pHdr = (const PXCH_IPC_MSGHDR_HOSTNAMEANDIPS*)chMessageBuf;
	if (!MsgIsType(HOSTNAMEANDIPS, chMessageBuf)) return ERROR_INVALID_PARAMETER;

	if (pHostname) *pHostname = pHdr->Hostname;
	if (pbWillMapResolvedIpToHost) *pbWillMapResolvedIpToHost = pHdr->dwWillMapResolvedIpToHost;
	if (pdwIpNum) *pdwIpNum = pHdr->dwIpNum;
	if (pdwPid) *pdwPid = pHdr->dwPid;
	if (pbWillProxy) *pbWillProxy = (BOOL)pHdr->dwWillProxy;
	
	if (Ips) CopyMemory(Ips, (const char*)chMessageBuf + sizeof(PXCH_IPC_MSGHDR_HOSTNAMEANDIPS), sizeof(PXCH_IP_ADDRESS) * pHdr->dwIpNum);
	return 0;
}
