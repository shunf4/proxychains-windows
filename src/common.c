#include "stdafx.h"
#include <strsafe.h>
#include "pxch_defines.h"
#include "common.h"
#include "log.h"
#include "ipc.h"

WCHAR szErrorMessage[MAX_ERROR_MESSAGE_BUFSIZE];

PWCHAR FormatErrorToStr(DWORD dwError)
{
	DWORD dwCb;
	HLOCAL hLocalBuffer;
	HMODULE hDll;

	DWORD neutralLocale = MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL);
	dwCb = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, neutralLocale, (LPWSTR)&hLocalBuffer, 0, NULL);
	if (dwCb) goto after_fmt;

	// Might be a network error
	hDll = LoadLibraryExW(L"netmsg.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (hDll != NULL) {
		dwCb = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, hDll, dwError, neutralLocale, (LPWSTR)&hLocalBuffer, 0, NULL);
		FreeLibrary(hDll);
	}

after_fmt:
	if (dwCb && hLocalBuffer != NULL) {
		PWSTR buf = (PWSTR)LocalLock(hLocalBuffer);
		if (buf[dwCb - 1] == L'\n') {
			buf[dwCb - 1] = L'\0';
		}
		if (buf[dwCb - 2] == L'\r') {
			buf[dwCb - 2] = L'\0';
		}
		StringCchPrintfW(szErrorMessage, MAX_ERROR_MESSAGE_BUFSIZE, L"%ls(" WPRDW L")", buf, dwError);
		LocalFree(hLocalBuffer);
	}
	else {
		StringCchPrintfW(szErrorMessage, MAX_ERROR_MESSAGE_BUFSIZE, L"(" WPRDW L")", dwError);
	}
	return szErrorMessage;
}


void PrintErrorToFile(FILE* f, DWORD dwError)
{
	FormatErrorToStr(dwError);
	fwprintf(f, L"Error: %ls\n", szErrorMessage);
}

DWORD WstrToMessage(IPC_MSGBUF chMessageBuf, DWORD* pcbMessageSize, PCWSTR szWstr)
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


DWORD MessageToWstr(PWSTR szWstr, CIPC_MSGBUF chMessageBuf, DWORD cbMessageSize)
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