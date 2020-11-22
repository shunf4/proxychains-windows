// SPDX-License-Identifier: GPL-2.0-or-later
/* proxychains_helper.c
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

#define STRSAFE_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS
#include "defines_win32.h"
#include "remote_win32.h"
#include <limits.h>

#ifdef __CYGWIN__
#define PREFIX_ZERO_X ""
#else
#define PREFIX_ZERO_X L"0x"
#endif

#if defined(_M_X64) || defined(__x86_64__)
#define SUFFIX_ARCH L"X64"
#define MACHINE_WORD_SIZE 8
#else
#define SUFFIX_ARCH L"X86"
#define MACHINE_WORD_SIZE 4
#endif

int ReplaceStartMarker(char** ppInput, size_t* pcbInputRemaining, char** ppOutput, size_t* pcbOutputRemaining, char** ppOutputStartAddress)
{
#if defined(_M_X64) || defined(__x86_64__)
	// movabs register, imm64
	static char cInst[] = "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00";
	static char cInstMatchMask[] = "\xFF\xF8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	static PXCH_UINT_MACHINE* pInstAddr = (PXCH_UINT_MACHINE*)(cInst + 2);

	// push rbp
	// sub rsp, 1024
	// lea rbp, [rsp+512]
	static const char cSubstitute[] = "\x55\x48\x81\xEC\x00\x04\x00\x00\x48\x8D\xAC\x24\x00\x02\x00\x00";
#else
	// mov QWORD PTR [register+0x??], imm32
	static char cInst[] = "\xc7\x45\xf4\x00\x00\x00\x00";
	static char cInstMatchMask[] = "\xFF\x00\x00\xFF\xFF\xFF\xFF";
	static PXCH_UINT_MACHINE* pInstAddr = (PXCH_UINT_MACHINE*)(cInst + 3);

	// push ebp
	// sub esp, 1024
	// lea ebp, [esp+512]
	static const char cSubstitute[] = "\x55\x81\xEC\x00\x04\x00\x00\x8D\xAC\x24\x00\x02\x00\x00";
#endif

	static char cInstBuf[sizeof(cInst)];
	static const size_t cbInst = sizeof(cInst) - 1;
	static const size_t cbSubstitute = sizeof(cSubstitute) - 1;
	char* pInput = *ppInput;
	const char* pInst = cInst;
	const char* pMask = cInstMatchMask;
	char* pBuf = cInstBuf;

	if (*pcbInputRemaining < cbInst) return 0;

	if (*pInstAddr == 0) {
		*pInstAddr = PXCH_POINTER_PLACEHOLDER_STARTMARKER;
	}

	for (; pInput < (*ppInput) + cbInst; pInput++, pMask++, pBuf++) {
		*pBuf = *pInput & *pMask;
	}

	for (pInst = cInst, pBuf = cInstBuf, pMask = cInstMatchMask; pBuf < cInstBuf + cbInst; pInst++, pBuf++, pMask++) {
		if ((*pInst & *pMask) != *pBuf) {
			return 0;
		}
	}

	if (*pcbOutputRemaining < cbSubstitute) {
		fwprintf(stderr, L"Error: Entry detour output buf insufficient.\n");
		exit(4);
	}

	if (*ppOutputStartAddress) {
		fwprintf(stderr, L"Error: Duplicate start mark found in Entry detour.\n");
		exit(4);
	}

	*ppOutputStartAddress = *ppOutput;
	memcpy(*ppOutput, cSubstitute, cbSubstitute);
	*ppOutput += cbSubstitute;
	*pcbOutputRemaining -= cbSubstitute;

	*ppInput += cbInst;
	*pcbInputRemaining -= cbInst;

	return 1;
}


int AppendJmpAfterReturnAddressAssign(char** ppInput, size_t* pcbInputRemaining, char** ppOutput, size_t* pcbOutputRemaining, char** ppOutputEndAddress, char** pp_pReturnAddr)
{
#if defined(_M_X64) || defined(__x86_64__)
	// movabs r??, imm64
	static char cInst[] = "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00";
	static const char cInstMatchMask[] = "\xFF\xF8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
	static PXCH_UINT_MACHINE* pInstAddr = (PXCH_UINT_MACHINE*)(cInst + 2);
	static const size_t cbInputRegisterNoOffset = 1;
	static const char cbRegisterNoMask = '\x07';

	// add rsp, 1024
	// pop rbp
	// jmp r??
	const char cInsert[] = "\x48\x81\xC4\x00\x04\x00\x00\x5D\xFF\xE0";
	static const size_t cbInsertRegisterNoOffset = 9;
#else
	// or eax, imm32
	static char cInst[] = "\x0d\x00\x00\x00\x00";
	static const char cInstMatchMask[] = "\xFF\xFF\xFF\xFF\xFF";
	static PXCH_UINT_MACHINE* pInstAddr = (PXCH_UINT_MACHINE*)(cInst + 1);
	static const size_t cbInputRegisterNoOffset = 0;
	static const char cbRegisterNoMask = '\x00';

	// add esp, 1024
	// pop ebp
	// jmp eax
	const char cInsert[] = "\x81\xC4\x00\x04\x00\x00\x5D\xFF\xE0";
	static const size_t cbInsertRegisterNoOffset = 0;
#endif

	static char cInstBuf[sizeof(cInst)];
	static const size_t cbInst = sizeof(cInst) - 1;
	static const size_t cbInsert = sizeof(cInsert) - 1;

	char* pInput = *ppInput;
	const char* pInst = cInst;
	const char* pMask = cInstMatchMask;
	char* pBuf = cInstBuf;
	char RegisterNo;

	if (*pcbInputRemaining < cbInst) return 0;

	if (*pInstAddr == 0) {
		*pInstAddr = PXCH_POINTER_PLACEHOLDER_PRETURNADDR;
	}

	for (; pInput < (*ppInput) + cbInst; pInput++, pMask++, pBuf++) {
		*pBuf = *pInput & *pMask;
	}

	for (pInst = cInst, pBuf = cInstBuf, pMask = cInstMatchMask; pBuf < cInstBuf + cbInst; pInst++, pBuf++, pMask++) {
		if ((*pInst & *pMask) != *pBuf) {
			return 0;
		}
	}

	if (*pcbOutputRemaining < cbInst + cbInsert) {
		fwprintf(stderr, L"Error: Entry detour output buf insufficient.\n");
		exit(4);
	}

	if (*ppOutputEndAddress || *pp_pReturnAddr) {
		fwprintf(stderr, L"Error: Duplicate end mark found in Entry detour.\n");
		exit(4);
	}

	RegisterNo = *(*ppInput + cbInputRegisterNoOffset) & cbRegisterNoMask;

	*pp_pReturnAddr = *ppOutput + ((char*)pInstAddr - cInst);

	memcpy(*ppOutput, *ppInput, cbInst);
	*ppOutput += cbInst;
	*pcbOutputRemaining -= cbInst;

	memcpy(*ppOutput, cInsert, cbInsert);
	*(*ppOutput + cbInsertRegisterNoOffset) |= RegisterNo;

	*ppOutput += cbInsert;
	*pcbOutputRemaining -= cbInsert;

	*ppOutputEndAddress = *ppOutput;

	*ppInput += cbInst;
	*pcbInputRemaining -= cbInst;

	return 1;
}

int AppendJmpAfterReturnAddressAssignAlt(char** ppInput, size_t* pcbInputRemaining, char** ppOutput, size_t* pcbOutputRemaining, char** ppOutputEndAddress, char** pp_pReturnAddr)
{
#if defined(_M_X64) || defined(__x86_64__)
	return 0;
#else
	// or e??, imm32
	static char cInst[] = "\x81\xca\x00\x00\x00\x00";
	static const char cInstMatchMask[] = "\xFF\xF8\xFF\xFF\xFF\xFF";
	static PXCH_UINT_MACHINE* pInstAddr = (PXCH_UINT_MACHINE*)(cInst + 2);
	static const size_t cbInputRegisterNoOffset = 1;
	static const char cbRegisterNoMask = '\x07';

	// add esp, 1024
	// pop ebp
	// jmp e??
	const char cInsert[] = "\x81\xC4\x00\x04\x00\x00\x5D\xFF\xE0";
	static const size_t cbInsertRegisterNoOffset = 8;

	static char cInstBuf[sizeof(cInst)];
	static const size_t cbInst = sizeof(cInst) - 1;
	static const size_t cbInsert = sizeof(cInsert) - 1;
	

	char* pInput = *ppInput;
	const char* pInst = cInst;
	const char* pMask = cInstMatchMask;
	char* pBuf = cInstBuf;
	char RegisterNo;

	if (*pcbInputRemaining < cbInst) return 0;

	if (*pInstAddr == 0) {
		*pInstAddr = PXCH_POINTER_PLACEHOLDER_PRETURNADDR;
	}

	for (; pInput < (*ppInput) + cbInst; pInput++, pMask++, pBuf++) {
		*pBuf = *pInput & *pMask;
	}

	for (pInst = cInst, pBuf = cInstBuf, pMask = cInstMatchMask; pBuf < cInstBuf + cbInst; pInst++, pBuf++, pMask++) {
		if ((*pInst & *pMask) != *pBuf) {
			return 0;
		}
	}

	if (*pcbOutputRemaining < cbInst + cbInsert) {
		fwprintf(stderr, L"Error: Entry detour output buf insufficient.\n");
		exit(4);
	}

	if (*ppOutputEndAddress || *pp_pReturnAddr) {
		fwprintf(stderr, L"Error: Duplicate end mark found in Entry detour.\n");
		exit(4);
	}

	RegisterNo = *(*ppInput + cbInputRegisterNoOffset) & cbRegisterNoMask;

	*pp_pReturnAddr = *ppOutput + ((char*)pInstAddr - cInst);

	memcpy(*ppOutput, *ppInput, cbInst);
	*ppOutput += cbInst;
	*pcbOutputRemaining -= cbInst;

	memcpy(*ppOutput, cInsert, cbInsert);
	*(*ppOutput + cbInsertRegisterNoOffset) |= RegisterNo;

	*ppOutput += cbInsert;
	*pcbOutputRemaining -= cbInsert;

	*ppOutputEndAddress = *ppOutput;

	*ppInput += cbInst;
	*pcbInputRemaining -= cbInst;

	return 1;
#endif
}


int main(int argc, const char* const* argv)
{
	if (argc != 2) return 1;
	
	if (strcmp(argv[1], "--get-winapi-func-addr") == 0) {
#if defined(_M_X64) || defined(__x86_64__)
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
		wprintf(L"%llX\n", 0ULL);
#else
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&GetModuleHandleW);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&LoadLibraryW);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&GetProcAddress);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&FreeLibrary);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&GetLastError);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&OutputDebugStringA);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&GetCurrentProcessId);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&wsprintfA);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&Sleep);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&ExitThread);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&ReleaseSemaphore);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&CloseHandle);
		wprintf(L"%llX\n", (unsigned long long)(uintptr_t)&WaitForSingleObject);
#endif
		return 0;
	}

	if (strcmp(argv[1], "--dump-functions") == 0) {
		char* pCode;
		char* pAfterCode;
		SSIZE_T cbCodeSize;
		SSIZE_T cbCodeSizeAligned;
		SSIZE_T cb;

		// Print HookDll loader (remote function)

		pCode = (char*)LoadHookDll;
		pAfterCode = (char*)LoadHookDll_End;

		if (*(BYTE*)pCode == 0xE9) {
			fwprintf(stderr, L"Warning: Remote function body is a JMP instruction! This is usually caused by \"incremental linking\". hough this is correctly handled now, there might be problems in the future. Try to disable that.\n");
			pCode = (void*)((char*)pCode + *(DWORD*)((char*)pCode + 1) + 5);
		}

		if (*(BYTE*)pAfterCode == 0xE9) {
			pAfterCode = (void*)((char*)pAfterCode + *(DWORD*)((char*)pAfterCode + 1) + 5);
		}

		cbCodeSize = ((char*)pAfterCode - (char*)pCode);
		cbCodeSizeAligned = (cbCodeSize + (sizeof(LONG_PTR) - 1)) & ~(sizeof(LONG_PTR) - 1);

		wprintf(L"static const char g_RemoteFunc" SUFFIX_ARCH L"[] = \"");

		for (cb = 0; cb < cbCodeSizeAligned; cb++) {
			wprintf(L"\\x%02hhX", ((char*)pCode)[cb]);
		}

		wprintf(L"\";\n\n");

		// Print Entry detour

		pCode = (char*)EntryDetour;
		pAfterCode = (char*)EntryDetour_End;

		if (*(BYTE*)pCode == 0xE9) {
			fwprintf(stderr, L"!!!Warning: Entry detour body is a JMP instruction! This is usually caused by \"incremental linking\". hough this is handled now(?), there might be problems in the future. Try to disable that.\n");
			fwprintf(stderr, L"!!!Warning: Entry detour body is a JMP instruction! This is usually caused by \"incremental linking\". hough this is handled now(?), there might be problems in the future. Try to disable that.\n");
			fwprintf(stderr, L"!!!Warning: Entry detour body is a JMP instruction! This is usually caused by \"incremental linking\". hough this is handled now(?), there might be problems in the future. Try to disable that.\n");
			pCode = (void*)((char*)pCode + *(DWORD*)((char*)pCode + 1) + 5);
		}

		if (*(BYTE*)pAfterCode == 0xE9) {
			pAfterCode = (void*)((char*)pAfterCode + *(DWORD*)((char*)pAfterCode + 1) + 5);
		}

		cbCodeSize = ((char*)pAfterCode - (char*)pCode);
		cbCodeSizeAligned = (cbCodeSize + (sizeof(LONG_PTR) - 1)) & ~(sizeof(LONG_PTR) - 1);

		{
			char* pInput;
			size_t cbInputRemaining;
			char* pOutput;
			size_t cbOutputRemaining;
			char cEntryDetourBin[2048];

			char* pOutputStartAddress;
			char* pOutputEndAddress;
			char* p_pReturnAddr;
			char* p_pRemoteData;

			pInput = pCode;
			cbInputRemaining = pAfterCode - pCode;
			pOutput = cEntryDetourBin;
			cbOutputRemaining = sizeof(cEntryDetourBin);

			pOutputStartAddress = pOutputEndAddress = p_pReturnAddr = p_pRemoteData = NULL;

			// Scan: recognize start & end, tailor the func code to output

			while (1) {
				if (ReplaceStartMarker(&pInput, &cbInputRemaining, &pOutput, &cbOutputRemaining, &pOutputStartAddress)) {
					;
				} else if (AppendJmpAfterReturnAddressAssign(&pInput, &cbInputRemaining, &pOutput, &cbOutputRemaining, &pOutputEndAddress, &p_pReturnAddr)) {
					;
				} else if (AppendJmpAfterReturnAddressAssignAlt(&pInput, &cbInputRemaining, &pOutput, &cbOutputRemaining, &pOutputEndAddress, &p_pReturnAddr)) {
					;
				} else {
					if (cbInputRemaining >= MACHINE_WORD_SIZE && (*(PXCH_UINT_MACHINE*)pInput) == PXCH_POINTER_PLACEHOLDER_PREMOTEDATA) {
						if (p_pRemoteData != NULL) {
							fwprintf(stderr, L"Error: redundant pRemoteData placeholder 0x%llx in entry detour machine code.\n", (unsigned long long)PXCH_POINTER_PLACEHOLDER_PREMOTEDATA);
							return 2;
						}
						p_pRemoteData = pOutput;
					}

					*pOutput = *pInput;
					pOutput++;
					cbOutputRemaining--;
					pInput++;
					cbInputRemaining--;

					if (cbInputRemaining == 0) break;
					if (cbOutputRemaining == 0) {
						fwprintf(stderr, L"Error: Entry detour output buf insufficient.\n");
						return 4;
					}
				}
			}

			wprintf(L"static const char g_OriginalEntryDetour" SUFFIX_ARCH L"[] = \"");
		
			for (pInput = pCode; pInput != pCode + cbCodeSizeAligned; pInput++) {
				wprintf(L"\\x%02hhX", *pInput);
			}

			wprintf(L"\";\n\n");

			if (pOutputStartAddress == NULL) {
				fwprintf(stderr, L"Error: Start mark not found in entry detour machine code.\n");
				return 3;
			}

			if (pOutputEndAddress == NULL || pOutputEndAddress <= pOutputStartAddress) {
				fwprintf(stderr, L"Error: End mark not found or less than start mark in entry detour machine code.\n");
				return 3;
			}

			if (p_pRemoteData == NULL || p_pRemoteData < pOutputStartAddress || p_pRemoteData >= pOutputEndAddress) {
				fwprintf(stderr, L"Error: pRemoteData placeholder 0x%llx not found or at wrong place in entry detour machine code.\n", (unsigned long long)PXCH_POINTER_PLACEHOLDER_PREMOTEDATA);
				return 3;
			}

			if (p_pReturnAddr == NULL || p_pReturnAddr < pOutputStartAddress || p_pReturnAddr >= pOutputEndAddress) {
				fwprintf(stderr, L"Error: pReturnAddr placeholder 0x%llx (end mark) not found or at wrong place in entry detour machine code.\n", (unsigned long long)PXCH_POINTER_PLACEHOLDER_PRETURNADDR);
				return 3;
			}

			wprintf(L"static const char g_EntryDetour" SUFFIX_ARCH L"[] = \"");

			cbCodeSize = pOutputEndAddress - pOutputStartAddress;
			cbCodeSizeAligned = (cbCodeSize + (sizeof(LONG_PTR) - 1)) & ~(sizeof(LONG_PTR) - 1);
		
			for (pOutput = pOutputStartAddress; pOutput != pOutputStartAddress + cbCodeSizeAligned; pOutput++) {
				wprintf(L"\\x%02hhX", *pOutput);
			}

			wprintf(L"\";\n\n");

			wprintf(L"static const size_t g_EntryDetour_cbpRemoteDataOffset" SUFFIX_ARCH L" = 0x%zx;\n", p_pRemoteData - pOutputStartAddress);
			wprintf(L"static const size_t g_EntryDetour_cbpReturnAddrOffset" SUFFIX_ARCH L" = 0x%zx;\n", p_pReturnAddr - pOutputStartAddress);
		}

		fflush(stdout);
		return 0;
	}

	return 1;
}