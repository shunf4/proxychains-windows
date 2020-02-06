#include "includes_win32.h"
#include "log_win32.h"
#include "hookdll_win32.h"
#include "proc_bookkeeping_win32.h"

#include <WinSock2.h>
#include <Ws2Tcpip.h>

tab_per_process_t* g_tabPerProcess;
HANDLE g_hDataMutex;
tab_fake_ip_hostname_t* g_tabFakeIpHostname;


DWORD ChildProcessExitedCallbackWorker(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
	LOCKED({
		tab_per_process_t * Entry = (tab_per_process_t*)lpParameter;
		tab_fake_ip_hostname_t IpHostnameAsKey;
		tab_fake_ip_hostname_t* IpHostnameEntry;
		IpNode* pIpNode;
		IpNode* pTmpIpNode;

		DWORD dwExitCode = UINT32_MAX;
		HASH_DELETE(hh, g_tabPerProcess, Entry);
		if (!GetExitCodeProcess(Entry->hProcess, &dwExitCode)) {
			LOGE(L"GetExitCodeProcess() error: %ls", FormatErrorToStr(GetLastError()));
		}
		LOGI(L"Child process winpid " WPRDW L" exited (%#010x).", Entry->Data.dwPid, dwExitCode);

		LL_FOREACH_SAFE(Entry->Ips, pIpNode, pTmpIpNode){
			IpHostnameAsKey.Ip = pIpNode->Ip;
			IpHostnameAsKey.dwOptionalPid = Entry->Data.dwPid;
			HASH_FIND(hh, g_tabFakeIpHostname, &IpHostnameAsKey.Ip, sizeof(PXCH_IP_ADDRESS) + sizeof(PXCH_UINT32), IpHostnameEntry);
			if (IpHostnameEntry) {
				HASH_DELETE(hh, g_tabFakeIpHostname, IpHostnameEntry);
				HeapFree(GetProcessHeap(), 0, IpHostnameEntry);
			}

			if (g_pPxchConfig->bDeleteFakeIpAfterChildProcessExits) {
				IpHostnameAsKey.dwOptionalPid = 0;
				HASH_FIND(hh, g_tabFakeIpHostname, &IpHostnameAsKey.Ip, sizeof(PXCH_IP_ADDRESS) + sizeof(PXCH_UINT32), IpHostnameEntry);
				if (IpHostnameEntry) {
					HASH_DELETE(hh, g_tabFakeIpHostname, IpHostnameEntry);
					HeapFree(GetProcessHeap(), 0, IpHostnameEntry);
				}
			}

			LL_DELETE(Entry->Ips, pIpNode);
			HeapFree(GetProcessHeap(), 0, pIpNode);
		}

		HeapFree(GetProcessHeap(), 0, Entry);

		if (g_tabPerProcess == NULL) {
			LOGI(L"All windows descendant process exited.");
			IF_WIN32_EXIT(0);
		}

		goto after_proc;
	});
}


VOID CALLBACK ChildProcessExitedCallback(
	_In_ PVOID   lpParameter,
	_In_ BOOLEAN TimerOrWaitFired
)
{
	ChildProcessExitedCallbackWorker(lpParameter, TimerOrWaitFired);
}

DWORD RegisterNewChildProcess(const REPORTED_CHILD_DATA* pChildData)
{
	LOCKED({
		tab_per_process_t* Entry;
		HANDLE hWaitHandle;
		HANDLE hChildHandle;

		LOGV(L"Before HeapAlloc...");
		Entry = (tab_per_process_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(tab_per_process_t));
		LOGV(L"After HeapAlloc...");
		if ((hChildHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, pChildData->dwPid)) == NULL) {
			dwReturn = GetLastError();
			if (dwReturn == ERROR_ACCESS_DENIED) {
				if ((hChildHandle = OpenProcess(SYNCHRONIZE, FALSE, pChildData->dwPid)) == NULL) {
					dwReturn = GetLastError();
				} else {
					goto after_open_process;
				}
			}
			LOGC(L"OpenProcess() error: %ls", FormatErrorToStr(dwReturn));
			goto after_proc;
		}
	after_open_process:
		LOGD(L"After OpenProcess(" WPRDW L")...", hChildHandle);

		if (!RegisterWaitForSingleObject(&hWaitHandle, hChildHandle, &ChildProcessExitedCallback, Entry, INFINITE, WT_EXECUTELONGFUNCTION | WT_EXECUTEONLYONCE)) {
			dwReturn = GetLastError();
			LOGC(L"RegisterWaitForSingleObject() error: %ls", FormatErrorToStr(dwReturn));
			goto after_proc;
		}
		LOGV(L"After RegisterWaitForSingleObject...");
		Entry->Data = *pChildData;
		Entry->hProcess = hChildHandle;
		Entry->Ips = NULL;
		LOGV(L"After Entry->Data = *pChildData;");
		HASH_ADD(hh, g_tabPerProcess, Data, sizeof(pid_key_t), Entry);
		LOGV(L"After HASH_ADD");
		LOGI(L"Registered child pid " WPRDW, pChildData->dwPid);
	});
}

DWORD QueryChildStorage(REPORTED_CHILD_DATA* pChildData)
{
	LOCKED({
		tab_per_process_t* Entry;
		HASH_FIND(hh, g_tabPerProcess, &pChildData->dwPid, sizeof(pid_key_t), Entry);
		if (Entry) {
			*pChildData = Entry->Data;
		}

		goto after_proc;
	});
}

void IndexToIp(PXCH_IP_ADDRESS* pIp, PXCH_UINT32 iIndex)
{
	PXCH_HOST* pHost = (PXCH_HOST*)&g_pPxchConfig->FakeIpRange;
	ZeroMemory(pIp, sizeof(PXCH_IP_ADDRESS));
	if (HostIsType(IPV4, *pHost)) {
		struct sockaddr_in* pIpv4 = (struct sockaddr_in*)pIp;
		pIpv4->sin_family = PXCH_HOST_TYPE_IPV4;
		PXCH_UINT32 dwMaskInvert;
		PXCH_UINT32 dwToShift = g_pPxchConfig->dwFakeIpRangePrefix > 32 ? 0 : 32 - g_pPxchConfig->dwFakeIpRangePrefix;

		pIpv4->sin_addr = ((struct sockaddr_in*) & g_pPxchConfig->FakeIpRange)->sin_addr;
		dwMaskInvert = htonl((PXCH_UINT32)((((PXCH_UINT64)1) << dwToShift) - 1));
		pIpv4->sin_addr.s_addr &= ~dwMaskInvert;
		pIpv4->sin_addr.s_addr |= (htonl(iIndex) & dwMaskInvert);
		return;
	}

	if (HostIsType(IPV6, *pHost)) {
		struct sockaddr_in6* pIpv6 = (struct sockaddr_in6*)pIp;
		pIpv6->sin6_family = PXCH_HOST_TYPE_IPV6;
		PXCH_UINT32 dwMaskInvert;
		struct {
			PXCH_UINT64 First64;
			PXCH_UINT64 Last64;
		} MaskInvert, *pIpv6AddrInQwords;

		PXCH_UINT32 dwToShift = g_pPxchConfig->dwFakeIpRangePrefix > 128 ? 0 : 128 - g_pPxchConfig->dwFakeIpRangePrefix;
		PXCH_UINT32 dwShift1 = dwToShift >= 64 ? 64 : dwToShift;
		PXCH_UINT32 dwShift2 = dwToShift >= 64 ? (dwToShift - 64) : 0;

		MaskInvert.Last64 = dwShift1 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift1) - 1);
		MaskInvert.First64 = dwShift2 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift2) - 1);

		if (LITTLEENDIAN) {
			MaskInvert.Last64 = _byteswap_uint64(MaskInvert.Last64);
			MaskInvert.First64 = _byteswap_uint64(MaskInvert.First64);
		}


		pIpv6->sin6_addr = ((struct sockaddr_in6*) & g_pPxchConfig->FakeIpRange)->sin6_addr;
		pIpv6AddrInQwords = (void*)&pIpv6->sin6_addr;
		pIpv6AddrInQwords->First64 &= ~MaskInvert.First64;
		pIpv6AddrInQwords->Last64 &= ~MaskInvert.Last64;
		pIpv6AddrInQwords->Last64 |= (htonl(iIndex) & MaskInvert.Last64);
		return;
	}
}

void IpToIndex(PXCH_UINT32* piIndex, const PXCH_IP_ADDRESS* pIp)
{
	PXCH_HOST* pHost = (PXCH_HOST*)&g_pPxchConfig->FakeIpRange;
	PXCH_HOST* pInHost = (PXCH_HOST*)pIp;
	if (HostIsType(IPV4, *pHost) && HostIsType(IPV4, *pInHost)) {
		struct sockaddr_in* pIpv4 = (struct sockaddr_in*)pIp;
		PXCH_UINT32 dwMaskInvert;
		PXCH_UINT32 dwToShift = g_pPxchConfig->dwFakeIpRangePrefix > 32 ? 0 : 32 - g_pPxchConfig->dwFakeIpRangePrefix;

		dwMaskInvert = htonl((PXCH_UINT32)((((PXCH_UINT64)1) << dwToShift) - 1));
		*piIndex = pIpv4->sin_addr.s_addr & dwMaskInvert;
		return;
	}

	if (HostIsType(IPV6, *pHost) && HostIsType(IPV6, *pInHost)) {
		struct sockaddr_in6* pIpv6 = (struct sockaddr_in6*)pIp;
		PXCH_UINT32 dwMaskInvert;
		struct {
			PXCH_UINT64 First64;
			PXCH_UINT64 Last64;
		} MaskInvert, * pIpv6AddrInQwords;

		PXCH_UINT32 dwToShift = g_pPxchConfig->dwFakeIpRangePrefix > 128 ? 0 : 128 - g_pPxchConfig->dwFakeIpRangePrefix;
		PXCH_UINT32 dwShift1 = dwToShift >= 64 ? 64 : dwToShift;
		PXCH_UINT32 dwShift2 = dwToShift >= 64 ? (dwToShift - 64) : 0;

		MaskInvert.Last64 = dwShift1 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift1) - 1);
		MaskInvert.First64 = dwShift2 == 64 ? 0xFFFFFFFFFFFFFFFFU : ((((PXCH_UINT64)1) << dwShift2) - 1);

		if (LITTLEENDIAN) {
			MaskInvert.Last64 = _byteswap_uint64(MaskInvert.Last64);
			MaskInvert.First64 = _byteswap_uint64(MaskInvert.First64);
		}

		pIpv6AddrInQwords = (void*)&pIpv6->sin6_addr;

		*piIndex = (PXCH_UINT32)(pIpv6AddrInQwords->Last64 & MaskInvert.Last64);
		return;
	}

	*piIndex = -1;
}

DWORD NextAvailableFakeIp(PXCH_IP_ADDRESS* pFakeIp)
{
	static PXCH_UINT64 iSearch = 1;

	LOCKED({
		PXCH_UINT64 iSearchWhenEnter;
		PXCH_IP_ADDRESS IpSearch;
		tab_fake_ip_hostname_t AsKey;
		tab_fake_ip_hostname_t * Entry;
		AsKey.dwOptionalPid = 0;

		iSearchWhenEnter = iSearch;

		while (1) {
			Entry = NULL;
			IndexToIp(&AsKey.Ip, iSearch);
			HASH_FIND(hh, g_tabFakeIpHostname, &AsKey.Ip, sizeof(PXCH_IP_ADDRESS) + sizeof(PXCH_UINT32), Entry);
			if (!Entry) break;
			iSearch++;
			if (iSearch >= ((PXCH_UINT64)1 << (32 - g_pPxchConfig->dwFakeIpRangePrefix)) - 1) {
				iSearch = 1;
			}

			if (iSearch == iSearchWhenEnter) {
				dwReturn = ERROR_RESOURCE_NOT_AVAILABLE;
				goto after_proc;
			}
		}

		*pFakeIp = AsKey.Ip;
		dwReturn = NO_ERROR;
	});
}

DWORD RegisterHostnameAndGetFakeIp(PXCH_IP_ADDRESS* pFakeIp, const tab_fake_ip_hostname_t* TempEntry, PXCH_UINT32 dwPid, BOOL bWillMapResolvedIpToHost)
{
	LOCKED({
		tab_fake_ip_hostname_t* FakeIpEntry;
		tab_fake_ip_hostname_t* ResolvedIpEntry;
		tab_per_process_t* CurrentProcessDataEntry;
		IpNode* pIpNode;
		DWORD dwErrorCode;
		DWORD dw;

		CurrentProcessDataEntry = NULL;
		HASH_FIND(hh, g_tabPerProcess, &dwPid, sizeof(dwPid), CurrentProcessDataEntry);

		if (CurrentProcessDataEntry == NULL) goto err_no_proc_entry;

		pIpNode = (IpNode*)HeapAlloc(GetProcessHeap(), 0, sizeof(IpNode));
		dwErrorCode = NextAvailableFakeIp(&pIpNode->Ip);
		if (dwErrorCode != NO_ERROR) goto err_no_avail_fake_ip;
		LL_PREPEND(CurrentProcessDataEntry->Ips, pIpNode);
	
		FakeIpEntry = (tab_fake_ip_hostname_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(tab_fake_ip_hostname_t));
		FakeIpEntry->Ip = pIpNode->Ip;
		FakeIpEntry->dwOptionalPid = 0;
		FakeIpEntry->Hostname = TempEntry->Hostname;
		FakeIpEntry->dwResovledIpNum = TempEntry->dwResovledIpNum;
		CopyMemory(FakeIpEntry->ResolvedIps, TempEntry->ResolvedIps, sizeof(PXCH_IP_ADDRESS) * FakeIpEntry->dwResovledIpNum);

		HASH_ADD(hh, g_tabFakeIpHostname, Ip, sizeof(PXCH_IP_ADDRESS) + sizeof(PXCH_UINT32), FakeIpEntry);
	
		if (bWillMapResolvedIpToHost) {
			for (dw = 0; dw < FakeIpEntry->dwResovledIpNum; dw++) {
				pIpNode = (IpNode*)HeapAlloc(GetProcessHeap(), 0, sizeof(IpNode));
				pIpNode->Ip = TempEntry->ResolvedIps[dw];
				LL_PREPEND(CurrentProcessDataEntry->Ips, pIpNode);

				ResolvedIpEntry = (tab_fake_ip_hostname_t*)HeapAlloc(GetProcessHeap(), 0, sizeof(tab_fake_ip_hostname_t));
				ResolvedIpEntry->Ip = TempEntry->ResolvedIps[dw];
				ResolvedIpEntry->dwOptionalPid = dwPid;
				ResolvedIpEntry->Hostname = TempEntry->Hostname;
				ResolvedIpEntry->dwResovledIpNum = TempEntry->dwResovledIpNum;
				CopyMemory(ResolvedIpEntry->ResolvedIps, TempEntry->ResolvedIps, sizeof(PXCH_IP_ADDRESS) * FakeIpEntry->dwResovledIpNum);

				HASH_ADD(hh, g_tabFakeIpHostname, Ip, sizeof(PXCH_IP_ADDRESS) + sizeof(PXCH_UINT32), ResolvedIpEntry);
			}
		}

		dwReturn = NO_ERROR;
		goto after_proc;

	err_no_proc_entry:
		dwReturn = ERROR_NOT_FOUND;
		goto after_proc;

	err_no_avail_fake_ip:
		goto ret_free;

	ret_free:
		HeapFree(GetProcessHeap(), 0, pIpNode);
		dwReturn = dwErrorCode;
		goto after_proc;
	});
}

DWORD GetMsgHostnameAndResolvedIpFromMsgIp(IPC_MSGBUF chMessageBuf, PXCH_UINT32 *pcbMessageSize, const IPC_MSGHDR_IPADDRESS* pMsgIp)
{
	tab_fake_ip_hostname_t AsKey;
	tab_fake_ip_hostname_t* Entry;
	DWORD dwErrorCode;

	AsKey.Ip = pMsgIp->Ip;
	AsKey.dwOptionalPid = pMsgIp->dwPid;

	Entry = NULL;
	HASH_FIND(hh, g_tabFakeIpHostname, &AsKey.Ip, sizeof(PXCH_IP_ADDRESS) + sizeof(PXCH_UINT32), Entry);

	if (Entry == NULL) return ERROR_NOT_FOUND;

	HostnameAndResolvedIpToMessage(chMessageBuf, pcbMessageSize, pMsgIp->dwPid, &Entry->Hostname, FALSE /*ignored*/, Entry->dwResovledIpNum, Entry->ResolvedIps);

	return NO_ERROR;

err_not_found:
	return ERROR_NOT_FOUND;
}

DWORD HandleMessage(int i, IPC_INSTANCE* pipc)
{
	IPC_MSGBUF* pMsg = (IPC_MSGBUF*)pipc->chReadBuf;

	if (MsgIsType(WSTR, pMsg)) {
		WCHAR sz[IPC_BUFSIZE / sizeof(WCHAR)];
		MessageToWstr(sz, pMsg, pipc->cbRead);
		StdWprintf(STD_ERROR_HANDLE, L"%ls", sz);
		StdFlush(STD_ERROR_HANDLE);

		goto after_handling_resp_ok;
	}

	if (MsgIsType(CHILDDATA, pMsg)) {
		REPORTED_CHILD_DATA ChildData;
		LOGV(L"Message is CHILDDATA");
		MessageToChildData(&ChildData, pMsg, pipc->cbRead);
		LOGD(L"Child process pid " WPRDW L" created.", ChildData.dwPid);
		LOGV(L"RegisterNewChildProcess...");
		RegisterNewChildProcess(&ChildData);
		LOGV(L"RegisterNewChildProcess done.");
		goto after_handling_resp_ok;
	}

	if (MsgIsType(QUERYSTORAGE, pMsg)) {
		REPORTED_CHILD_DATA ChildData = { 0 };
		LOGV(L"Message is QUERYSTORAGE");
		MessageToQueryStorage(&ChildData.dwPid, pMsg, pipc->cbRead);
		QueryChildStorage(&ChildData);
		ChildDataToMessage(pipc->chWriteBuf, &pipc->cbToWrite, &ChildData);
		goto ret;
	}

	if (MsgIsType(HOSTNAMEANDRESOLVEDIP, pMsg)) {
		BOOL bWillMapResolvedIpToHost;
		PXCH_UINT32 dwPid;
		tab_fake_ip_hostname_t Entry;
		PXCH_IP_ADDRESS FakeIp = { 0 };
		
		LOGV(L"Message is HOSTNAMEANDRESOLVEDIP");
		MessageToHostnameAndResolvedIp(&dwPid, &Entry.Hostname, &bWillMapResolvedIpToHost, &Entry.dwResovledIpNum, &Entry.ResolvedIps, pMsg, pipc->cbRead);
		if (RegisterHostnameAndGetFakeIp(&FakeIp, &Entry, dwPid, bWillMapResolvedIpToHost) != NO_ERROR) LOGE(L"RegisterHostnameAndGetFakeIp() failed");
		IpAddressToMessage(pipc->chWriteBuf, &pipc->cbToWrite, 0 /*ignored*/, &FakeIp);
		goto ret;
	}

	if (MsgIsType(IPADDRESS, pMsg)) {
		BOOL bWillMapResolvedIpToHost;
		PXCH_UINT32 dwPid;
		tab_fake_ip_hostname_t Entry;
		PXCH_HOSTNAME Hostname;

		LOGV(L"Message is IPADDRESS");
		if (GetMsgHostnameAndResolvedIpFromMsgIp(pipc->chWriteBuf, &pipc->cbToWrite, (const IPC_MSGHDR_IPADDRESS*)pMsg) != NO_ERROR) LOGE(L"GetHostnameFromIp() failed");
		goto ret;
	}

	goto after_handling_not_recognized;

after_handling_resp_ok:
	WstrToMessage(pipc->chWriteBuf, &pipc->cbToWrite, L"OK");
	return 0;

after_handling_not_recognized:
	WstrToMessage(pipc->chWriteBuf, &pipc->cbToWrite, L"NOT RECOGNIZED");
	return 0;

ret:
	return 0;
}


DWORD InitProcessBookkeeping(void)
{
	g_tabPerProcess = NULL;
	g_tabFakeIpHostname = NULL;

	if ((g_hDataMutex = CreateMutexW(NULL, FALSE, NULL)) == NULL) return GetLastError();

	return 0;
}
