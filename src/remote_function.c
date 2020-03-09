// SPDX-License-Identifier: GPL-2.0-or-later
/* remote_function.c
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
#include "defines_win32.h"
#include "remote_win32.h"

DWORD __stdcall LoadHookDll(LPVOID* pArg)
{
	((FpSleep)(((PXCH_INJECT_REMOTE_DATA*)pArg)->pxchConfig.FunctionPointers.fpSleepX64))(100);
	((PXCH_INJECT_REMOTE_DATA*)pArg)->chDebugOutputBuf[((PXCH_INJECT_REMOTE_DATA*)pArg)->cbDebugOutputCharOffset] = 'A';
	((FpOutputDebugStringA)(((PXCH_INJECT_REMOTE_DATA*)pArg)->pxchConfig.FunctionPointers.fpOutputDebugStringAX64))(((PXCH_INJECT_REMOTE_DATA*)pArg)->chDebugOutputBuf);
	unsigned long long i;
	for (i = 0; i < 5000000000ULL; i++)
		if (i % 1000000 == 0 && i / 1000000 < 5) {
			((PXCH_INJECT_REMOTE_DATA*)pArg)->chDebugOutputBuf[((PXCH_INJECT_REMOTE_DATA*)pArg)->cbDebugOutputCharOffset] = 'A' + (i % 26);
			((PXCH_INJECT_REMOTE_DATA*)pArg)->chDebugOutputBuf[0] = ' ';
			((FpOutputDebugStringA)(((PXCH_INJECT_REMOTE_DATA*)pArg)->pxchConfig.FunctionPointers.fpOutputDebugStringAX64))(((PXCH_INJECT_REMOTE_DATA*)pArg)->chDebugOutputBuf);
		}

	((PXCH_INJECT_REMOTE_DATA*)pArg)->chDebugOutputBuf[0] = 'W';
	((PXCH_INJECT_REMOTE_DATA*)pArg)->chDebugOutputBuf[((PXCH_INJECT_REMOTE_DATA*)pArg)->cbDebugOutputCharOffset] = 'A' + (i % 26);
	((FpOutputDebugStringA)(((PXCH_INJECT_REMOTE_DATA*)pArg)->pxchConfig.FunctionPointers.fpOutputDebugStringAX64))(((PXCH_INJECT_REMOTE_DATA*)pArg)->chDebugOutputBuf);
	return -4;
	// Arrays are not allowed here. To reserve padding for cygtls, we substract rbp and rsp
	// Since we modified the stack frame, there is no normal way to exit this thread (return) except calling ExitThread()
#if (defined(_M_X64) || defined(__x86_64__)) && 0
	__asm__("sub $0x8000, %rbp\n\t"
        "sub $0x8000, %rsp\n\t");
#endif

	PXCH_INJECT_REMOTE_DATA* pRemoteData;
	HMODULE hHookDllModule;
	FARPROC fpInitFunc;
	LPVOID pbCurrentlyInWinapiCall;

	// Pass the argument to pRemoteData at the right(after reservation) position
#if (defined(_M_X64) || defined(__x86_64__)) && 0
	__asm__("mov %%rcx, %0"
		: "=r"(pRemoteData)
		:
	);
#endif

	// if (((PXCH_INJECT_REMOTE_DATA*)pArg)->dwDebugDepth >= 2) { ((FpExitThread)(((PXCH_INJECT_REMOTE_DATA*)pArg)->pxchConfig.FunctionPointers.fpExitThreadX64))(-3); return -1; }

	pRemoteData = (PXCH_INJECT_REMOTE_DATA*)pArg;

	DBGSTEP('A');

	pRemoteData->dwEverExecuted = 1;

	DBGSTEP('B');

#ifdef __CYGWIN__
	{
		HMODULE hCygwinModule;
		void (*cyginit)();
#ifndef PXCH_IS_MSYS
		pRemoteData->dwLastError = ERROR_DLL_INIT_FAILED;
		hCygwinModule = CAST_FUNC_ADDR(LoadLibraryW)(pRemoteData->szCygwin1ModuleName);
		if (!hCygwinModule) {
			pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
			CAST_FUNC_ADDR(ExitThread)(pRemoteData->dwLastError);
			return -1; // To make compiler happy
		}
		
		pRemoteData->dwLastError = ERROR_PROC_NOT_FOUND;
		cyginit = (void (*)())CAST_FUNC_ADDR(GetProcAddress)(hCygwinModule, pRemoteData->szCygwin1InitFuncName);
		(void)cyginit;
		// (*cyginit)();
#else
		pRemoteData->dwLastError = ERROR_DLL_INIT_FAILED;
		hCygwinModule = CAST_FUNC_ADDR(LoadLibraryW)(pRemoteData->szMsys2ModuleName);
		if (!hCygwinModule) {
			pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
			CAST_FUNC_ADDR(ExitThread)(pRemoteData->dwLastError);
			return -1; // To make compiler happy
		}

		pRemoteData->dwLastError = ERROR_PROC_NOT_FOUND;
		cyginit = (void (*)())CAST_FUNC_ADDR(GetProcAddress)(hCygwinModule, pRemoteData->szCygwin1InitFuncName);
		(void)cyginit;
		// (*cyginit)();
#endif
	}
#endif
	
	DBGSTEP('C');

#ifdef PXCH_MINHOOK_USE_DYNAMIC
	{
		HMODULE hMinHookDllModule = NULL;

		if (pRemoteData->pxchConfig.szMinHookDllPath[0] != L'\0') {
			hMinHookDllModule = CAST_FUNC_ADDR(LoadLibraryW)(pRemoteData->pxchConfig.szMinHookDllPath);
			if (!hMinHookDllModule) {
				pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
				CAST_FUNC_ADDR(ExitThread)(pRemoteData->dwLastError);
				return -1; // To make compiler happy
			}
		}
	}
#endif
	
	DBGSTEP('D');

	// ???
	// hHookDllModule = CAST_FUNC_ADDR(GetModuleHandleW)(pRemoteData->szHookDllModuleName);
	// if (hHookDllModule) {
	// 	pRemoteData->dwLastError = ERROR_ALREADY_REGISTERED;
	// 	CAST_FUNC_ADDR(ExitThread)(ERROR_ALREADY_REGISTERED);
	//  return -1; // To make compiler happy
	// }

	DBGSTEP('E');

	pRemoteData->dwLastError = ERROR_DLL_INIT_FAILED;

	hHookDllModule = CAST_FUNC_ADDR(LoadLibraryW)(pRemoteData->pxchConfig.szHookDllPath);
	if (!hHookDllModule) {
		pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
		CAST_FUNC_ADDR(ExitThread)(pRemoteData->dwLastError);
		return -1; // To make compiler happy
	}

	DBGSTEP('F');

	pRemoteData->dwLastError = ERROR_PROC_NOT_FOUND;
	pbCurrentlyInWinapiCall = CAST_FUNC_ADDR(GetProcAddress)(hHookDllModule, pRemoteData->szCIWCVarName);
	if (!pbCurrentlyInWinapiCall) goto err_getprocaddress;
	*(BOOL*)pbCurrentlyInWinapiCall = TRUE;

	DBGSTEP('G');

	pRemoteData->dwLastError = ERROR_PROC_NOT_FOUND;
	fpInitFunc = CAST_FUNC_ADDR(GetProcAddress)(hHookDllModule, pRemoteData->szInitFuncName);
	if (!fpInitFunc) goto err_getprocaddress;

	DBGSTEP('H');

	if (1) { ((FpExitThread)(((PXCH_INJECT_REMOTE_DATA*)pArg)->pxchConfig.FunctionPointers.fpExitThreadX64))(-3); return -1; }

	pRemoteData->dwLastError = ERROR_FUNCTION_FAILED;
	if (!(((PXCH_INJECT_REMOTE_DATA*)pArg)->dwDebugDepth >= 2) || TRUE) {pRemoteData->dwLastError = ((DWORD(__stdcall*)(PXCH_INJECT_REMOTE_DATA*))fpInitFunc)(pRemoteData);}

	DBGSTEP('I');

	if (pRemoteData->dwLastError != NO_ERROR) goto err_init_func_failed;

	DBGSTEP('J');

	pRemoteData->dwLastError = 0;
	*(BOOL*)pbCurrentlyInWinapiCall = FALSE;

	DBGSTEP('K');

	CAST_FUNC_ADDR(ExitThread)(0);
	return -1; // To make compiler happy

err_init_func_failed:
	goto err_after_load_dll;

err_getprocaddress:
	pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
	goto err_after_load_dll;

err_after_load_dll:
	CAST_FUNC_ADDR(FreeLibrary)(hHookDllModule);
	CAST_FUNC_ADDR(ExitThread)(pRemoteData->dwLastError);
	return -1; // To make compiler happy
}


void* LoadHookDll_End(void)
{
	return LoadHookDll;
}


void __cdecl CygwinEntryDetour(void)
{
#if (defined(_M_X64) || defined(__x86_64__))
	PXCH_INJECT_REMOTE_DATA* pRemoteData = (void*)0xDEADBEEFFEEDFACE;
	void* pReturnAddr = (void*)0xCAFEBABEBAADF00D;
#endif

#if (defined(_M_X64) || defined(__x86_64__))
	asm volatile ("mov 8(%%rbp), %0" : "=r"(pReturnAddr) :);
#endif
}


void* CygwinEntryDetour_End(void)
{
	return CygwinEntryDetour;
}