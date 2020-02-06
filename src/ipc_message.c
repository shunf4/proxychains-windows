#include "ipc_win32.h"

PXCH_UINT32 WstrToMessage(IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, const wchar_t* szWstr)
{
	IPC_MSGHDR_WSTR* pHdr = (IPC_MSGHDR_WSTR*)chMessageBuf;
	PWCHAR szWstrEnd;

	pHdr->dwTag = IPC_MSGTYPE_WSTR;
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

	pHdr->dwTag = IPC_MSGTYPE_CHILDDATA;
	CopyMemory(&pHdr->ChildData, pChildData, sizeof(REPORTED_CHILD_DATA));
	*pcbMessageSize = sizeof(IPC_MSGHDR_CHILDDATA);
	return 0;
}

DWORD MessageToChildData(REPORTED_CHILD_DATA* pChildData, CIPC_MSGBUF chMessageBuf, DWORD cbMessageSize)
{
	const IPC_MSGHDR_CHILDDATA* pHdr = (const IPC_MSGHDR_CHILDDATA*)chMessageBuf;
	if (!MsgIsType(CHILDDATA, chMessageBuf)) return ERROR_INVALID_PARAMETER;
	CopyMemory(pChildData, &pHdr->ChildData, sizeof(REPORTED_CHILD_DATA));
	return 0;
}

DWORD QueryStorageToMessage(IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, DWORD dwChildPid)
{
	IPC_MSGHDR_QUERYSTORAGE* pHdr = (IPC_MSGHDR_QUERYSTORAGE*)chMessageBuf;

	pHdr->dwTag = IPC_MSGTYPE_QUERYSTORAGE;
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

PXCH_UINT32 HostnameAndResolvedIpToMessage(IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, PXCH_UINT32 dwPid, const PXCH_HOSTNAME* Hostname, BOOL bWillMapResolvedIpToHost, PXCH_UINT32 dwResolvedIpNum, const PXCH_IP_ADDRESS* ResolvedIps)
{
	IPC_MSGHDR_HOSTNAMEANDRESOLVEDIP* pHdr = (IPC_MSGHDR_HOSTNAMEANDRESOLVEDIP*)chMessageBuf;

	pHdr->dwTag = IPC_MSGTYPE_HOSTNAMEANDRESOLVEDIP;
	pHdr->dwResolvedIpNum = dwResolvedIpNum;
	pHdr->dwWillMapResolvedIpToHost = bWillMapResolvedIpToHost;
	pHdr->Hostname = *Hostname;
	pHdr->dwPid = dwPid;

	CopyMemory((char*)chMessageBuf + sizeof(IPC_MSGBUF), ResolvedIps, sizeof(PXCH_IP_ADDRESS) * dwResolvedIpNum);
	return 0;
}

PXCH_UINT32 MessageToHostnameAndResolvedIp(PXCH_UINT32* pdwPid, PXCH_HOSTNAME* pHostname, BOOL* pbWillMapResolvedIpToHost, PXCH_UINT32* pdwResolvedIpNum, PXCH_IP_ADDRESS* ResolvedIps, CIPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize)
{
	const IPC_MSGHDR_HOSTNAMEANDRESOLVEDIP* pHdr = (const IPC_MSGHDR_HOSTNAMEANDRESOLVEDIP*)chMessageBuf;
	if (!MsgIsType(HOSTNAMEANDRESOLVEDIP, chMessageBuf)) return ERROR_INVALID_PARAMETER;

	*pHostname = pHdr->Hostname;
	*pbWillMapResolvedIpToHost = pHdr->dwWillMapResolvedIpToHost;
	*pdwResolvedIpNum = pHdr->dwResolvedIpNum;
	*pdwPid = pHdr->dwPid;
	
	CopyMemory(ResolvedIps, (const char*)chMessageBuf + sizeof(IPC_MSGBUF), sizeof(PXCH_IP_ADDRESS) * pHdr->dwResolvedIpNum);
	return 0;
}

PXCH_UINT32 IpAddressToMessage(IPC_MSGBUF chMessageBuf, PXCH_UINT32* pcbMessageSize, PXCH_UINT32 dwPid, const PXCH_IP_ADDRESS* pIp)
{
	IPC_MSGHDR_IPADDRESS* pHdr = (IPC_MSGHDR_IPADDRESS*)chMessageBuf;

	pHdr->dwTag = IPC_MSGTYPE_IPADDRESS;
	pHdr->dwPid = dwPid;
	pHdr->Ip = *pIp;
	
	return 0;
}

PXCH_UINT32 MessageToIpAddress(PXCH_UINT32* pdwPid, PXCH_IP_ADDRESS* pIp, CIPC_MSGBUF chMessageBuf, PXCH_UINT32 cbMessageSize)
{
	const IPC_MSGHDR_IPADDRESS* pHdr = (const IPC_MSGHDR_IPADDRESS*)chMessageBuf;
	if (!MsgIsType(IPADDRESS, chMessageBuf)) return ERROR_INVALID_PARAMETER;

	*pdwPid = pHdr->dwPid;
	*pIp = pHdr->Ip;

	return 0;
}