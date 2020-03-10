// SPDX-License-Identifier: GPL-2.0-or-later
/* hookdll_main.c
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
#define _CRT_SECURE_NO_WARNINGS
#define PXCH_DO_NOT_INCLUDE_STRSAFE_NOW
#include "defines_win32.h"
#include "log_win32.h"
#include "hookdll_util_win32.h"
#include <MinHook.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include <winternl.h>
#include "hookdll_win32.h"

#if defined(_M_X64) || defined(__x86_64__) || !defined(__CYGWIN__)
#ifdef _DEBUG
#include "remote_func_bin_x64d.h"
#else // _DEBUG
#include "remote_func_bin_x64.h"
#endif // _DEBUG
#else // defined(_M_X64) || defined(__x86_64__) || !defined(__CYGWIN__)
static const char g_RemoteFuncX64[1];
static const char g_EntryDetourX64[1];
static const size_t g_EntryDetour_cbpRemoteDataOffsetX64 = 0x0;
static const size_t g_EntryDetour_cbpReturnAddrOffsetX64 = 0x0;
#endif // defined(_M_X64) || defined(__x86_64__) || !defined(__CYGWIN__)

#if !(defined(_M_X64) || defined(__x86_64__)) || !defined(__CYGWIN__)
#ifdef _DEBUG
#include "remote_func_bin_x86d.h"
#else // _DEBUG
#include "remote_func_bin_x86.h"
#endif // _DEBUG
#else // !(defined(_M_X64) || defined(__x86_64__)) || !defined(__CYGWIN__)
static const char g_RemoteFuncX86[1];
static const char g_EntryDetourX86[1];
static const size_t g_EntryDetour_cbpRemoteDataOffsetX86 = 0x0;
static const size_t g_EntryDetour_cbpReturnAddrOffsetX86 = 0x0;
#endif // !(defined(_M_X64) || defined(__x86_64__)) || !defined(__CYGWIN__)

#ifndef __CYGWIN__
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef LONG KPRIORITY;
#endif

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _WOW64_THREAD_UNKNOWN_STRUCT
{
   ULONG UnknownPrefix;
   WOW64_CONTEXT Wow64Context;
   ULONG UnknownSuffix;
} WOW64_THREAD_UNKNOWN_STRUCT, * PWOW64_THREAD_UNKNOWN_STRUCT;

typedef NTSTATUS (NTAPI* FpNtQueryInformationProcess)(HANDLE ProcessHandle,PROCESSINFOCLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength,PULONG ReturnLength);

typedef NTSTATUS (NTAPI* FpNtQueryInformationThread)(HANDLE ThreadHandle,THREADINFOCLASS ThreadInformationClass,PVOID ThreadInformation,ULONG ThreadInformationLength,PULONG ReturnLength);


PXCH_INJECT_REMOTE_DATA* g_pRemoteData;
PXCH_DLL_API PROXYCHAINS_CONFIG* g_pPxchConfig;
PXCH_DLL_API BOOL g_bCurrentlyInWinapiCall = FALSE;
UT_array* g_arrHeapAllocatedPointers;

FpNtQueryInformationProcess fpNtQueryInformationProcess;
FpNtQueryInformationThread fpNtQueryInformationThread;

// To verify that this process has its original data (not overwritten with those of parent by fork())
PXCH_DLL_API DWORD g_dwCurrentProcessIdForVerify;

DWORD RemoteCopyExecute(const PROCESS_INFORMATION* pPi, BOOL bIsWow64, BOOL bIsX86, PXCH_INJECT_REMOTE_DATA* pRemoteData)
{
	void* pTargetBuf;
	const void* pRemoteFuncCode;
	const void* pEntryDetourCode;
	char* pTargetRemoteFuncCode;
	char* pTargetEntryDetourCode;
	void* pTargetRemoteData;
	SIZE_T cbRemoteFuncCodeSize;
	SIZE_T cbEntryDetourCodeSize;
	SIZE_T cbWritten;
	SIZE_T cbRead;
	DWORD dwLastError;
	DWORD dwRemoteDataSize = pRemoteData->dwSize;

	// if (bIsX86) {
	// 	pRemoteFuncCode = PXCH_CONFIG_REMOTE_FUNC_X86(g_pPxchConfig);
	// 	cbRemoteFuncCodeSize = g_pPxchConfig->cbRemoteFuncX86Size;
	// } else {
	// 	pRemoteFuncCode = PXCH_CONFIG_REMOTE_FUNC_X64(g_pPxchConfig);
	// 	cbRemoteFuncCodeSize = g_pPxchConfig->cbRemoteFuncX64Size;
	// }
	if (bIsX86) {
		pRemoteFuncCode = g_RemoteFuncX86;
		pEntryDetourCode = g_EntryDetourX86;
		cbRemoteFuncCodeSize = sizeof(g_RemoteFuncX86) - 1;
		cbEntryDetourCodeSize = sizeof(g_EntryDetourX86) - 1;
	} else {
		pRemoteFuncCode = g_RemoteFuncX64;
		pEntryDetourCode = g_EntryDetourX64;
		cbRemoteFuncCodeSize = sizeof(g_RemoteFuncX64) - 1;
		cbEntryDetourCodeSize = sizeof(g_EntryDetourX64) - 1;
	}

	if (!cbRemoteFuncCodeSize) return ERROR_NOT_SUPPORTED;
	if (!cbEntryDetourCodeSize) return ERROR_NOT_SUPPORTED;

	IPCLOGV(L"CreateProcessW: Before VirtualAllocEx. %lld", (long long)cbRemoteFuncCodeSize);

	// Allocate memory (code + data) in remote process
	pTargetBuf = NULL;
	// pTargetBuf = (void*)0x40000000;
	pTargetBuf = VirtualAllocEx(pPi->hProcess, pTargetBuf, cbRemoteFuncCodeSize + cbEntryDetourCodeSize + dwRemoteDataSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pTargetBuf) goto err_alloc;

	IPCLOGV(L"CreateProcessW: After VirtualAllocEx. %p", pTargetBuf);

	// Write code
	IPCLOGV(L"RemoteFuncCode bin data: %ls", DumpMemory(pRemoteFuncCode, 16));
	IPCLOGV(L"EntryDetour bin data: %ls", DumpMemory(pEntryDetourCode, 16));
	pTargetRemoteFuncCode = pTargetBuf;
	pTargetEntryDetourCode = (char *)pTargetBuf + cbRemoteFuncCodeSize;
	if (!WriteProcessMemory(pPi->hProcess, pTargetRemoteFuncCode, pRemoteFuncCode, cbRemoteFuncCodeSize, &cbWritten) || cbWritten != cbRemoteFuncCodeSize) goto err_write_code;
	if (!WriteProcessMemory(pPi->hProcess, pTargetEntryDetourCode, pEntryDetourCode, cbEntryDetourCodeSize, &cbWritten) || cbWritten != cbEntryDetourCodeSize) goto err_write_code;

	IPCLOGV(L"CreateProcessW: After Write Code. " WPRDW, cbWritten);

	// We will write data later
	pTargetRemoteData = (char *)pTargetBuf + cbRemoteFuncCodeSize + cbEntryDetourCodeSize;

#if PXCH_USE_REMOTE_THREAD_INSTEAD_OF_ENTRY_DETOUR
	{
		DWORD dwReturn;
		HANDLE hRemoteThread;
		DWORD dwRemoteTid;
		IPCLOGV(L"CreateProcessW: Before CreateRemoteThread. " WPRDW, 0);

		// Create remote thread in target process to execute the code
		hRemoteThread = CreateRemoteThread(pPi->hProcess, NULL, 0, pTargetRemoteFuncCode, pTargetRemoteData, CREATE_SUSPENDED, &dwRemoteTid);
		IPCLOGV(L"CreateProcessW: After CreateRemoteThread(). Tid: " WPRDW, dwRemoteTid);
		if (!hRemoteThread) goto err_create_remote_thread;

		// Make remote function step format string and write data
		StringCchPrintfA(pRemoteData->chDebugOutputBuf, _countof(pRemoteData->chDebugOutputBuf), "[pid %" PRIdword "] [tid %" PRIdword "] : in step ? in remote func process", pPi->dwProcessId, dwRemoteTid);
		pRemoteData->cbDebugOutputCharOffset = (PXCH_UINT32)(StrChrA(pRemoteData->chDebugOutputBuf, '?') - pRemoteData->chDebugOutputBuf);

		if (!WriteProcessMemory(pPi->hProcess, pTargetRemoteData, pRemoteData, dwRemoteDataSize, &cbWritten) || cbWritten != dwRemoteDataSize) goto err_write_data_remote_thread;

		IPCLOGV(L"CreateProcessW: After Write Data. " WPRDW, cbWritten);

		ResumeThread(hRemoteThread);

		// Wait for the thread to exit
		if ((dwReturn = WaitForSingleObject(hRemoteThread, INFINITE)) != WAIT_OBJECT_0) goto err_wait;

		IPCLOGV(L"CreateProcessW: After WaitForSingleObject(). " WPRDW, 0);
		dwReturn = -1;
		if (!GetExitCodeThread(hRemoteThread, &dwReturn)) {
			IPCLOGE(L"GetExitCodeThread() Error: %ls", FormatErrorToStr(GetLastError()));
		}

		if (dwReturn != 0) {
			IPCLOGE(L"Error: Remote thread exit code: %#lx", dwReturn);
		}

		// Copy back data
		FillMemory(pRemoteData, dwRemoteDataSize, 0xFF);
		if (!ReadProcessMemory(pPi->hProcess, pTargetRemoteData, pRemoteData, dwRemoteDataSize, &cbRead) || cbRead != dwRemoteDataSize) goto err_read_data_remote_thread;

		// Validate return value
		if (dwReturn != pRemoteData->dwLastError) {
			IPCLOGE(L"Error: Remote thread exit code does not match the error code stored in remote data memory! Exit code:" WPRDW L" <=> Data Memory: %ls", dwReturn, FormatErrorToStr(pRemoteData->dwLastError));
		}

		return 0;
		
	err_create_remote_thread:
		dwLastError = GetLastError();
		IPCLOGE(L"CreateRemoteThread() Failed: %ls", FormatErrorToStr(dwLastError));
		goto ret_free;

	err_wait:
		dwLastError = GetLastError();
		IPCLOGE(L"WaitForSingleObject() Failed: " WPRDW L", %ls", dwReturn, FormatErrorToStr(dwLastError));
		goto ret_close;
	
	err_read_data_remote_thread:
		dwLastError = GetLastError();
		IPCLOGE(L"ReadProcessMemory() Failed to read data(" WPRDW L"/" WPRDW L"): %ls", cbRead, dwRemoteDataSize, FormatErrorToStr(dwLastError));
		goto ret_close;

	err_write_data_remote_thread:
		dwLastError = GetLastError();
		IPCLOGE(L"WriteProcessMemory() Failed to write data: %ls", FormatErrorToStr(dwLastError));
		goto ret_free;

	ret_close:
		CloseHandle(hRemoteThread);
		goto ret_free;
	}
#else // PXCH_USE_REMOTE_THREAD_INSTEAD_OF_ENTRY_DETOUR
	{
		NTSTATUS NtStatusQuery;
		PROCESS_BASIC_INFORMATION Pbi;
		THREAD_BASIC_INFORMATION Tbi;
		PEB* pTargetPeb;
		DWORD pTargetWow64Peb;
		CONTEXT TargetCtx = {0};
		WOW64_CONTEXT TargetWow64Ctx = {0};
		WOW64_CONTEXT TargetWow64CtxFromTeb = {0};
		PWOW64_THREAD_UNKNOWN_STRUCT pTargetWow64UnknownStructFromTeb = NULL;
		char* pTargetImageBase;
		char* pTargetOriginalEntry;
		LONG cbLongFileAddressNew;
		IMAGE_NT_HEADERS32* pTargetImageNtHeaders32 = NULL;
		IMAGE_NT_HEADERS64* pTargetImageNtHeaders64 = NULL;
		WORD wTargetMachine;
		DWORD dwTargetOffsetOfEntryPoint;
		HANDLE hSemaphore1;
		HANDLE hSemaphore2;
		HANDLE hTargetSemaphore1;
		HANDLE hTargetSemaphore2;
		DWORD dwWaitResult;

		if (fpNtQueryInformationProcess == NULL || fpNtQueryInformationThread == NULL) {
			HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));

			if (!hNtDll) goto err_load_dll_entry_detour;

			fpNtQueryInformationProcess = (FpNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

			fpNtQueryInformationThread = (FpNtQueryInformationThread)GetProcAddress(hNtDll, "NtQueryInformationThread");

			if (fpNtQueryInformationProcess == NULL || fpNtQueryInformationThread == NULL) {
				IPCLOGW(L"Getting NtQueryInformationProcess addr failed! Won't try getting and injecting any more.");
				fpNtQueryInformationProcess = (void*)MAXUINT_PTR;
				fpNtQueryInformationThread = (void*)MAXUINT_PTR;
			}
		}

		if (fpNtQueryInformationProcess == (void*)MAXUINT_PTR || fpNtQueryInformationThread == (void*)MAXUINT_PTR) {
			return ERROR_NOT_SUPPORTED;
		}

		NtStatusQuery = (*fpNtQueryInformationProcess)(pPi->hProcess, ProcessBasicInformation, &Pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	
		if (!NT_SUCCESS(NtStatusQuery)) goto err_query;

		NtStatusQuery = (*fpNtQueryInformationThread)(pPi->hThread, 0/* ThreadBasicInformation */, &Tbi, sizeof(THREAD_BASIC_INFORMATION), 0);

		if (!NT_SUCCESS(NtStatusQuery)) goto err_query;

		TargetCtx.ContextFlags = CONTEXT_ALL;
		TargetWow64Ctx.ContextFlags = WOW64_CONTEXT_ALL;

#if !defined (__WIDL__) && _WIN32_WINNT >= 0x0600
#define PXCH_TARGETWOW64CTX_INVALID_PREFIX L""
		if (bIsWow64) {
			if (!Wow64GetThreadContext(pPi->hThread, &TargetWow64Ctx)) goto err_get_ctx;
		}
#else
#define PXCH_TARGETWOW64CTX_INVALID_PREFIX L"(Invalid)"
		(void)TargetWow64Ctx;
#endif

		if (!GetThreadContext(pPi->hThread, &TargetCtx)) goto err_get_ctx;

		pTargetPeb = Pbi.PebBaseAddress;

#if defined(_M_X64) || defined(__x86_64__)
		if (bIsWow64) {
			IPCLOGD(L"pTargetPeb: %p, TargetCtx.Rax - Rdx: %p %p %p %p, " PXCH_TARGETWOW64CTX_INVALID_PREFIX "TargetWow64Ctx.Eax - Edx: %p %p %p %p.", pTargetPeb, (void*)(uintptr_t)TargetCtx.Rax, (void*)(uintptr_t)TargetCtx.Rbx, (void*)(uintptr_t)TargetCtx.Rcx, (void*)(uintptr_t)TargetCtx.Rdx, (void*)(uintptr_t)TargetWow64Ctx.Eax, (void*)(uintptr_t)TargetWow64Ctx.Ebx, (void*)(uintptr_t)TargetWow64Ctx.Ecx, (void*)(uintptr_t)TargetWow64Ctx.Edx);

			if (TargetCtx.SegCs != 0x23 /* WOW64_CS32 */) {
				// Now target is in x64 mode, get stored Wow registers
				if (!ReadProcessMemory(pPi->hProcess, &((TEB*)(Tbi.TebBaseAddress))->TlsSlots[1], &pTargetWow64UnknownStructFromTeb, sizeof(PWOW64_THREAD_UNKNOWN_STRUCT), &cbRead) || cbRead != sizeof(PWOW64_THREAD_UNKNOWN_STRUCT)) goto err_read_entry_detour;

				if (!ReadProcessMemory(pPi->hProcess, &pTargetWow64UnknownStructFromTeb->Wow64Context, &TargetWow64CtxFromTeb, sizeof(WOW64_CONTEXT), &cbRead) || cbRead != sizeof(WOW64_CONTEXT)) goto err_read_entry_detour;

				IPCLOGD(L"TargetWow64CtxFromTeb.Eax - Edx: %p %p %p %p.", (void*)(uintptr_t)TargetWow64CtxFromTeb.Eax, (void*)(uintptr_t)TargetWow64CtxFromTeb.Ebx, (void*)(uintptr_t)TargetWow64CtxFromTeb.Ecx, (void*)(uintptr_t)TargetWow64CtxFromTeb.Edx);
			}

			if (!ReadProcessMemory(pPi->hProcess, ((char*)Tbi.TebBaseAddress + 0x2000 + 48) /* &TEB ==(+0x2000)==> &TEB32; get &TEB32::ProcessEnvironmentBlock */, &pTargetWow64Peb, sizeof(DWORD), &cbRead) || cbRead != sizeof(DWORD)) goto err_read_entry_detour;

			IPCLOGD(L"pTargetWow64Peb: %p", (void*)(uintptr_t)pTargetWow64Peb);

			if (pTargetWow64Peb != TargetWow64CtxFromTeb.Ebx) goto err_reg_ppeb_not_equal;
		} else {
			IPCLOGD(L"pTargetPeb: %p, TargetCtx.Rax - Rdx: %p %p %p %p.", pTargetPeb, (void*)(uintptr_t)TargetCtx.Rax, (void*)(uintptr_t)TargetCtx.Rbx, (void*)(uintptr_t)TargetCtx.Rcx, (void*)(uintptr_t)TargetCtx.Rdx);
			if (pTargetPeb != (void*)(uintptr_t)TargetCtx.Rdx) goto err_reg_ppeb_not_equal;
		}
#else
		if (bIsWow64) {
			(void)TargetWow64CtxFromTeb;
			(void)pTargetWow64UnknownStructFromTeb;
			(void)pTargetWow64Peb;

			IPCLOGD(L"pTargetPeb: %p, TargetCtx.Eax - Edx: %p %p %p %p.  " PXCH_TARGETWOW64CTX_INVALID_PREFIX "TargetWow64Ctx.Eax - Edx: %p %p %p %p.", pTargetPeb, (void*)(uintptr_t)TargetCtx.Eax, (void*)(uintptr_t)TargetCtx.Ebx, (void*)(uintptr_t)TargetCtx.Ecx, (void*)(uintptr_t)TargetCtx.Edx, (void*)(uintptr_t)TargetWow64Ctx.Eax, (void*)(uintptr_t)TargetWow64Ctx.Ebx, (void*)(uintptr_t)TargetWow64Ctx.Ecx, (void*)(uintptr_t)TargetWow64Ctx.Edx);

			if (pTargetPeb != (void*)(uintptr_t)TargetCtx.Ebx) goto err_reg_ppeb_not_equal;
		} else {
			(void)TargetWow64Ctx;
			(void)TargetWow64CtxFromTeb;
			(void)pTargetWow64UnknownStructFromTeb;
			(void)pTargetWow64Peb;
			IPCLOGD(L"pTargetPeb: %p, TargetCtx.Eax - Edx: %p %p %p %p.", pTargetPeb, (void*)(uintptr_t)TargetCtx.Eax, (void*)(uintptr_t)TargetCtx.Ebx, (void*)(uintptr_t)TargetCtx.Ecx, (void*)(uintptr_t)TargetCtx.Edx);
			if (pTargetPeb != (void*)(uintptr_t)TargetCtx.Ebx) goto err_reg_ppeb_not_equal;
		}
#endif

		if (!ReadProcessMemory(pPi->hProcess, &pTargetPeb->Reserved3[1] /* Image base address */, &pTargetImageBase, sizeof(char*), &cbRead) || cbRead != sizeof(char*)) goto err_read_entry_detour;

		if (!ReadProcessMemory(pPi->hProcess, &((IMAGE_DOS_HEADER*)pTargetImageBase)->e_lfanew, &cbLongFileAddressNew, sizeof(LONG), &cbRead) || cbRead != sizeof(LONG)) goto err_read_entry_detour;

		if (bIsX86) {
			pTargetImageNtHeaders32 = (void*)(pTargetImageBase + cbLongFileAddressNew);

			if (!ReadProcessMemory(pPi->hProcess, &pTargetImageNtHeaders32->FileHeader.Machine, &wTargetMachine, sizeof(WORD), &cbRead) || cbRead != sizeof(WORD)) goto err_read_entry_detour;

			if (wTargetMachine != IMAGE_FILE_MACHINE_I386) goto err_unmatched_machine;

			if (!ReadProcessMemory(pPi->hProcess, &pTargetImageNtHeaders32->OptionalHeader.AddressOfEntryPoint, &dwTargetOffsetOfEntryPoint, sizeof(DWORD), &cbRead) || cbRead != sizeof(DWORD)) goto err_read_entry_detour;
		} else {
			pTargetImageNtHeaders64 = (void*)(pTargetImageBase + cbLongFileAddressNew);

			if (!ReadProcessMemory(pPi->hProcess, &pTargetImageNtHeaders64->FileHeader.Machine, &wTargetMachine, sizeof(WORD), &cbRead) || cbRead != sizeof(WORD)) goto err_read_entry_detour;

			if (wTargetMachine != IMAGE_FILE_MACHINE_AMD64) goto err_unmatched_machine;

			if (!ReadProcessMemory(pPi->hProcess, &pTargetImageNtHeaders64->OptionalHeader.AddressOfEntryPoint, &dwTargetOffsetOfEntryPoint, sizeof(DWORD), &cbRead) || cbRead != sizeof(DWORD)) goto err_read_entry_detour;
		}

		pTargetOriginalEntry = pTargetImageBase + dwTargetOffsetOfEntryPoint;

		IPCLOGD(L"pTargetOriginalEntry: %p", pTargetOriginalEntry);

#if defined(_M_X64) || defined(__x86_64__)
		if (bIsWow64) {
			if (pTargetOriginalEntry != (char*)(uintptr_t)TargetWow64CtxFromTeb.Eax) goto err_reg_entry_not_equal;
		} else {
			if (pTargetOriginalEntry != (char*)(uintptr_t)TargetCtx.Rcx) goto err_reg_entry_not_equal;
		}
#else
		if (pTargetOriginalEntry != (char*)(uintptr_t)TargetCtx.Eax) goto err_reg_entry_not_equal;
#endif

		// Make semaphore
		hSemaphore1 = CreateSemaphoreW(NULL, 0, 1, NULL);
		hSemaphore2 = CreateSemaphoreW(NULL, 0, 1, NULL);
		if (hSemaphore1 == NULL || hSemaphore1 == INVALID_HANDLE_VALUE || hSemaphore2 == NULL || hSemaphore2 == INVALID_HANDLE_VALUE) goto err_create_semaphore;
		if (!DuplicateHandle(GetCurrentProcess(), hSemaphore1, pPi->hProcess, &hTargetSemaphore1, 0, TRUE, DUPLICATE_SAME_ACCESS)) goto err_dup_semaphore;
		if (!DuplicateHandle(GetCurrentProcess(), hSemaphore2, pPi->hProcess, &hTargetSemaphore2, 0, TRUE, DUPLICATE_SAME_ACCESS)) goto err_dup_semaphore;
		pRemoteData->qwSemaphore1 = (PXCH_UINT64)(uintptr_t)hTargetSemaphore1;
		pRemoteData->qwSemaphore2 = (PXCH_UINT64)(uintptr_t)hTargetSemaphore2;

		// Make remote function step format string and write data
		StringCchPrintfA(pRemoteData->chDebugOutputBuf, _countof(pRemoteData->chDebugOutputBuf), "[pid %" PRIdword "] [maintid %" PRIdword "] : in step ? in remote func process", pPi->dwProcessId, pPi->dwThreadId);
		pRemoteData->cbDebugOutputCharOffset = (PXCH_UINT32)(StrChrA(pRemoteData->chDebugOutputBuf, '?') - pRemoteData->chDebugOutputBuf);

		if (!WriteProcessMemory(pPi->hProcess, pTargetRemoteData, pRemoteData, dwRemoteDataSize, &cbWritten) || cbWritten != dwRemoteDataSize) goto err_write_entry_detour;

		if (bIsX86) {
			DWORD pTargetRemoteDataCast32 = (DWORD)(uintptr_t)pTargetRemoteData;
			DWORD pTargetOriginalEntryCast32 = (DWORD)(uintptr_t)pTargetOriginalEntry;

			if (!WriteProcessMemory(pPi->hProcess, pTargetEntryDetourCode + g_EntryDetour_cbpRemoteDataOffsetX86, &pTargetRemoteDataCast32, 4, &cbWritten) || cbWritten != 4) goto err_write_entry_detour;

			if (!WriteProcessMemory(pPi->hProcess, pTargetEntryDetourCode + g_EntryDetour_cbpReturnAddrOffsetX86, &pTargetOriginalEntryCast32, 4, &cbWritten) || cbWritten != 4) goto err_write_entry_detour;
		} else {
			DWORD64 pTargetRemoteDataCast64 = (DWORD64)(uintptr_t)pTargetRemoteData;
			DWORD64 pTargetOriginalEntryCast64 = (DWORD64)(uintptr_t)pTargetOriginalEntry;

			if (!WriteProcessMemory(pPi->hProcess, pTargetEntryDetourCode + g_EntryDetour_cbpRemoteDataOffsetX64, &pTargetRemoteDataCast64, 8, &cbWritten) || cbWritten != 8) goto err_write_entry_detour;

			if (!WriteProcessMemory(pPi->hProcess, pTargetEntryDetourCode + g_EntryDetour_cbpReturnAddrOffsetX64, &pTargetOriginalEntryCast64, 8, &cbWritten) || cbWritten != 8) goto err_write_entry_detour;
		}

		IPCLOGV(L"CreateProcessW: After Write Data. " WPRDW, cbWritten);

		// Update the entry address

#if defined(_M_X64) || defined(__x86_64__)
		TargetCtx.Rcx = (DWORD64)(uintptr_t)pTargetEntryDetourCode;
		if (!SetThreadContext(pPi->hThread, &TargetCtx)) goto err_set_ctx;

		if (bIsWow64) {
			if (TargetCtx.SegCs != 0x23 /* WOW64_CS32 */) {
				TargetWow64CtxFromTeb.Eax = (DWORD)(uintptr_t)pTargetEntryDetourCode;
				if (!WriteProcessMemory(pPi->hProcess, &pTargetWow64UnknownStructFromTeb->Wow64Context, &TargetWow64CtxFromTeb, sizeof(WOW64_CONTEXT), &cbWritten) || cbWritten != sizeof(WOW64_CONTEXT)) goto err_write_entry_detour;
			}
		}
#else
		TargetCtx.Eax = (DWORD)(uintptr_t)pTargetEntryDetourCode;
		if (!SetThreadContext(pPi->hThread, &TargetCtx)) goto err_set_ctx;
#endif

		// ResumeThread, and wait for the child process
		ResumeThread(pPi->hThread);

		LOGV(L"Waiting for hSemaphore.");
		dwWaitResult = WaitForSingleObject(hSemaphore1, 3000);
		switch (dwWaitResult)
		{
		case WAIT_OBJECT_0:
			if (!ReleaseSemaphore(hSemaphore1, 1, NULL)) {
				dwLastError = GetLastError();
				LOGW(L"Release semaphore error: %ls", FormatErrorToStr(dwLastError));
			}
			ReleaseSemaphore(hSemaphore2, 1, NULL);
			break;

		case WAIT_ABANDONED:
			LOGW(L"Semaphore abandoned!");
			break;

		case WAIT_TIMEOUT:
			LOGW(L"Semaphore timeout!");
			break;

		default:
			dwLastError = GetLastError();
			LOGW(L"Wait for semaphore status: " WPRDW L"; error: %ls", dwWaitResult, FormatErrorToStr(dwLastError));
			break;
		}

		// Copy back data
		FillMemory(pRemoteData, dwRemoteDataSize, 0xFF);
		if (!ReadProcessMemory(pPi->hProcess, pTargetRemoteData, pRemoteData, dwRemoteDataSize, &cbRead) || cbRead != dwRemoteDataSize) goto err_read_entry_detour_close_sema;

		CloseHandle(hSemaphore1);
		CloseHandle(hSemaphore2);
		return 0;

	err_load_dll_entry_detour:
		dwLastError = GetLastError();
		IPCLOGE(L"LoadLibraryW() Failed: %ls", FormatErrorToStr(dwLastError));
		goto ret_free;

	err_query:
		dwLastError = GetLastError();
		IPCLOGE(L"NtQueryInformationProcess()/NtQueryInformationThread() Failed: %ls", FormatErrorToStr(dwLastError));
		goto ret_free;

	err_get_ctx:
		dwLastError = GetLastError();
		IPCLOGE(L"GetThreadContext() Failed: %ls", FormatErrorToStr(dwLastError));
		goto ret_free;

	err_reg_ppeb_not_equal:
		dwLastError = ERROR_NOT_SUPPORTED;
		IPCLOGE(L"pTargetPeb != TargetCtx.Rdx/Ebx. Unable to inject into this process.");
		goto ret_free;

	err_reg_entry_not_equal:
		dwLastError = ERROR_NOT_SUPPORTED;
		IPCLOGE(L"pOriginalEntry != TargetCtx.Rcx/Eax. Unable to inject into this process.");
		goto ret_free;

	err_read_entry_detour:
		dwLastError = GetLastError();
		IPCLOGE(L"ReadProcessMemory() Failed: %ls", FormatErrorToStr(dwLastError));
		goto ret_free;

	err_unmatched_machine:
		dwLastError = ERROR_NOT_SUPPORTED;
		IPCLOGE(L"Unmatched executable platform type!");
		goto ret_free;

	err_create_semaphore:
		dwLastError = GetLastError();
		IPCLOGE(L"CreateSemaphore() Failed: %ls", FormatErrorToStr(dwLastError));
		CloseHandle(hSemaphore1);
		CloseHandle(hSemaphore2);
		goto ret_free;

	err_dup_semaphore:
		dwLastError = GetLastError();
		IPCLOGE(L"DuplicateHandle() Failed: %ls", FormatErrorToStr(dwLastError));
		goto ret_close_sema;

	err_write_entry_detour:
		dwLastError = GetLastError();
		IPCLOGE(L"WriteProcessMemory() Failed: %ls", FormatErrorToStr(dwLastError));
		goto ret_close_sema;

	err_read_entry_detour_close_sema:
		dwLastError = GetLastError();
		IPCLOGE(L"ReadProcessMemory() Failed: %ls", FormatErrorToStr(dwLastError));
		goto ret_close_sema;

	err_set_ctx:
		dwLastError = GetLastError();
		IPCLOGE(L"SetThreadContext() Failed: %ls", FormatErrorToStr(dwLastError));
		goto ret_close_sema;

	ret_close_sema:
		CloseHandle(hSemaphore1);
		CloseHandle(hSemaphore2);
		goto ret_free;
	}
#endif // PXCH_USE_REMOTE_THREAD_INSTEAD_OF_ENTRY_DETOUR

err_alloc:
	dwLastError = GetLastError();
	IPCLOGE(L"VirtualAllocEx() Failed: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;

err_write_code:
	dwLastError = GetLastError();
	IPCLOGE(L"WriteProcessMemory() Failed to write code(cbWritten = %zu, cbRemoteFuncCodeSize = %zu): %ls", cbWritten, cbRemoteFuncCodeSize, FormatErrorToStr(dwLastError));
	goto ret_free;

ret_free:
	VirtualFreeEx(pPi->hProcess, pTargetBuf, 0, MEM_RELEASE);
	return dwLastError;
}

DWORD InjectTargetProcess(const PROCESS_INFORMATION* pPi)
{
	HANDLE hProcess;
	PXCH_INJECT_REMOTE_DATA* pRemoteData;
	DWORD dwLastError;
	DWORD dwReturn;
	DWORD dwExtraSize = PXCH_CONFIG_EXTRA_SIZE_G;
	BOOL bIsX86;
	BOOL bIsWow64 = 7;

	hProcess = pPi->hProcess;
	if (!IsWow64Process(hProcess, &bIsWow64)) goto err_wow64;
	
	if (!g_bSystemInfoInitialized) {
		GetNativeSystemInfo(&g_SystemInfo);
		g_bSystemInfoInitialized = TRUE;
	}

	bIsX86 = (g_SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL || bIsWow64);

	// Another method to inject X64 -> X86: https://github.com/OpenWireSec/metasploit/blob/master/external/source/meterpreter/source/common/arch/win/i386/base_inject.c
	if (bIsX86) {
		if (g_pPxchConfig->FunctionPointers.fpGetModuleHandleWX86 == 0) {
			IPCLOGD(L"Child is an X86(Win32) process (%u %u); function address missing: won't inject", g_SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL, bIsWow64);
			return NO_ERROR;
		} else {
			IPCLOGD(L"Child is an X86(Win32) process (%u %u).", g_SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL, bIsWow64);
		}
	} else {
		if (g_pPxchConfig->FunctionPointers.fpGetModuleHandleWX64 == 0) {
			IPCLOGD(L"Child is an X64 process; function address missing: won't inject");
			return NO_ERROR;
		} else {
			IPCLOGD(L"Child is an X64 process.");
		}
	}

	pRemoteData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PXCH_INJECT_REMOTE_DATA) + dwExtraSize);

	IPCLOGV(L"CreateProcessW: Entering InjectTargetProcess. %llu", (unsigned long long)(sizeof(*pRemoteData) + dwExtraSize));

	IPCLOGV(L"CreateProcessW: Before CopyMemory. " WPRDW, 0);

	CopyMemory(&pRemoteData->pxchConfig, g_pPxchConfig, sizeof(PROXYCHAINS_CONFIG) + dwExtraSize);

	IPCLOGV(L"CreateProcessW: After CopyMemory. " WPRDW, 0);

	pRemoteData->dwZero = 0;
	pRemoteData->dwLastError = -1;
	pRemoteData->dwParentPid = GetCurrentProcessId();

	pRemoteData->dwDebugDepth = g_pRemoteData ? g_pRemoteData->dwDebugDepth + 1 : 1;

	IPCLOGV(L"CreateProcessW: After remoteData assignment. " WPRDW, 0);

	StringCchCopyA(pRemoteData->szInitFuncName, _countof(pRemoteData->szInitFuncName), bIsX86 ? PXCH_INITHOOK_SYMBOL_NAME_X86 : PXCH_INITHOOK_SYMBOL_NAME_X64);
	StringCchCopyA(pRemoteData->szCIWCVarName, _countof(pRemoteData->szCIWCVarName), "g_bCurrentlyInWinapiCall");
	CopyMemory(pRemoteData->chDebugOutputStepData, g_pRemoteData ? g_pRemoteData->chDebugOutputStepData : "A\0B\0C\0D\0E\0F\0G\0H\0I\0J\0K\0L\0M\0N\0O\0P\0Q\0R\0S\0T\0", sizeof(pRemoteData->chDebugOutputStepData));
	StringCchCopyW(pRemoteData->szCygwin1ModuleName, _countof(pRemoteData->szCygwin1ModuleName), g_pRemoteData ? g_pRemoteData->szCygwin1ModuleName : L"cygwin1.dll");
	StringCchCopyW(pRemoteData->szMsys2ModuleName, _countof(pRemoteData->szMsys2ModuleName), g_pRemoteData ? g_pRemoteData->szMsys2ModuleName : L"msys-2.0.dll");
	StringCchCopyW(pRemoteData->szHookDllModuleName, _countof(pRemoteData->szHookDllModuleName), g_pRemoteData ? g_pRemoteData->szHookDllModuleName : g_szHookDllFileName);
	pRemoteData->dwEverExecuted = 0;
	pRemoteData->dwSize = sizeof(PXCH_INJECT_REMOTE_DATA) + dwExtraSize;

	IPCLOGD(L"%ls", pRemoteData->pxchConfig.szHookDllPath);

	IPCLOGV(L"CreateProcessW: After StringCchCopy. " WPRDW, 0);

	dwReturn = RemoteCopyExecute(pPi, bIsWow64, bIsX86, pRemoteData);

	if (dwReturn != 0) goto error;
	IPCLOGV(L"CreateProcessW: After RemoteCopyExecute. " WPRDW, 0);

	if (pRemoteData->dwEverExecuted == 0) {
		IPCLOGE(L"Error: Remote thread/entry detour never executed!");
		dwReturn = ERROR_FUNCTION_NOT_CALLED;
		// goto error;
	}

	if (pRemoteData->dwLastError != 0) {
		IPCLOGE(L"Error: Remote thread error: %ls!", FormatErrorToStr(pRemoteData->dwLastError));
		dwReturn = pRemoteData->dwLastError;
		goto error;
	}

	HeapFree(GetProcessHeap(), 0, pRemoteData);
	return 0;

err_wow64:
	dwLastError = GetLastError();
	IPCLOGE(L"IsWow64Process() Failed: %ls", FormatErrorToStr(dwLastError));
	return dwLastError;

error:
	HeapFree(GetProcessHeap(), 0, pRemoteData);
	return dwReturn;
}

PXCH_DLL_API DWORD __stdcall InitHookForMain(PROXYCHAINS_CONFIG* pPxchConfig)
{
	MH_Initialize();
	// CREATE_HOOK(CreateProcessA);
	CREATE_HOOK(CreateProcessW);
	// CREATE_HOOK(CreateProcessAsUserW);
	MH_EnableHook(MH_ALL_HOOKS);

	LOGD(L"Main Program Hooked!");
	return 0;
}

PXCH_DLL_API DWORD __stdcall InitHook(PXCH_INJECT_REMOTE_DATA* pRemoteData)
{
	DWORD dwLastError = 0;
	ODBGSTRLOGD(L"InitHook: begin of func");

	g_pPxchConfig = &pRemoteData->pxchConfig;
	g_pRemoteData = pRemoteData;
	ODBGSTRLOGD(L"InitHook: initialize utarray");
	utarray_new(g_arrHeapAllocatedPointers, &ut_ptr_icd);

	ODBGSTRLOGD(L"InitHook: start");

// #define PXCH_HOOK_CONDITION (g_pRemoteData->dwDebugDepth <= 3)
#define PXCH_HOOK_CONDITION (TRUE)
	if (PXCH_HOOK_CONDITION) {
		MH_Initialize();

#ifndef __CYGWIN__	// Hooking CreateProcessA under cygwin causes CreateProcessW WinError 2.
		CREATE_HOOK(CreateProcessA);
#endif
		CREATE_HOOK(CreateProcessW);
		// CREATE_HOOK(CreateProcessAsUserW);

		ODBGSTRLOGD(L"InitHook: hooked CreateProcess");

		IPCLOGD(L"(In InitHook) g_pRemoteData->dwDebugDepth = " WPRDW, g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);

		// ALL HOOKS MUST BE DONE HERE
		// AFTER fork() RESTORES DATA SEGMENT, MINHOOK IS IN UNCERTAIN STATE
		Win32HookWs2_32();
		//CygwinHook();

		ODBGSTRLOGD(L"InitHook: before MH_EnableHook");

		MH_EnableHook(MH_ALL_HOOKS);
	} else {
		IPCLOGD(L"(In InitHook) g_pRemoteData->dwDebugDepth = " WPRDW L", skipping hooking", g_pRemoteData ? g_pRemoteData->dwDebugDepth : -1);
	}
	
	ODBGSTRLOGD(L"InitHook: after MH_EnableHook");

	dwLastError = IpcClientRegisterChildProcess();

	if (dwLastError) {
		ODBGSTRLOGD(L"InitHook: after IpcClientRegisterChildProcess, IPC Failed");
	} else {
		ODBGSTRLOGD(L"InitHook: after IpcClientRegisterChildProcess, IPC Succeed");
	}

	IPCLOGD(L"I'm WINPID " WPRDW L" Hooked!", log_pid);

	g_dwCurrentProcessIdForVerify = GetCurrentProcessId();
	ODBGSTRLOGD(L"InitHook: end");
	return 0;
}

PXCH_DLL_API void UninitHook(void)
{
	MH_DisableHook(MH_ALL_HOOKS);
	MH_Uninitialize();

	IPCLOGD(L"I'm WINPID " WPRDW L" UnHooked!", log_pid);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	LPVOID pvData;
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		ODBGSTRLOGD(L"Initialize TLS");
		if ((g_dwTlsIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
			return FALSE;
		}
		// No break: initailize the index for the main thread.
	case DLL_THREAD_ATTACH:
		if (g_dwTlsIndex != TLS_OUT_OF_INDEXES) {
			pvData = HeapAlloc(GetProcessHeap(), 0, PXCH_TLS_TOTAL_SIZE);
			TlsSetValue(g_dwTlsIndex, pvData);
		}

		break;
	case DLL_THREAD_DETACH:
		pvData = TlsGetValue(g_dwTlsIndex);
		HeapFree(GetProcessHeap(), 0, pvData);
		break;
	case DLL_PROCESS_DETACH:
		pvData = TlsGetValue(g_dwTlsIndex);
		HeapFree(GetProcessHeap(), 0, pvData);
		TlsFree(g_dwTlsIndex);
		break;
	}

	return TRUE;
}