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
	// Arrays are not allowed here
	PXCH_INJECT_REMOTE_DATA* pRemoteData = (PXCH_INJECT_REMOTE_DATA*)pArg;
	HMODULE hHookDllModule;
	FARPROC fpInitFunc;
	LPVOID pbCurrentlyInWinapiCall;

	DBGSTEP('A');

	pRemoteData->dwEverExecuted = 1;

	DBGSTEP('B');


	DBGSTEP('C');

#ifdef PXCH_MINHOOK_USE_DYNAMIC
	{
		HMODULE hMinHookDllModule = NULL;

		if (pRemoteData->pxchConfig.szMinHookDllPath[0] != L'\0') {
			hMinHookDllModule = CAST_FUNC_ADDR(LoadLibraryW)(pRemoteData->pxchConfig.szMinHookDllPath);
			if (!hMinHookDllModule) {
				pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
				return pRemoteData->dwLastError;
			}
		}
	}
#endif
	
	DBGSTEP('D');

	// ???
	// hHookDllModule = CAST_FUNC_ADDR(GetModuleHandleW)(pRemoteData->szHookDllModuleName);
	// if (hHookDllModule) {
	// 	pRemoteData->dwLastError = ERROR_ALREADY_REGISTERED;
	// 	return ERROR_ALREADY_REGISTERED;
	// }

	DBGSTEP('E');

	pRemoteData->dwLastError = ERROR_DLL_INIT_FAILED;

	hHookDllModule = CAST_FUNC_ADDR(LoadLibraryW)(pRemoteData->pxchConfig.szHookDllPath);
	if (!hHookDllModule) {
		pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
		return pRemoteData->dwLastError;
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

	pRemoteData->dwLastError = ERROR_FUNCTION_FAILED;
	pRemoteData->dwLastError = ((DWORD(__stdcall*)(PXCH_INJECT_REMOTE_DATA*))fpInitFunc)(pRemoteData);

	DBGSTEP('I');

	if (pRemoteData->dwLastError != NO_ERROR) goto err_init_func_failed;

	DBGSTEP('J');

	pRemoteData->dwLastError = 0;
	*(BOOL*)pbCurrentlyInWinapiCall = FALSE;

	DBGSTEP('K');

	return 0;

err_init_func_failed:
	goto err_after_load_dll;

err_getprocaddress:
	pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
	goto err_after_load_dll;

err_after_load_dll:
	CAST_FUNC_ADDR(FreeLibrary)(hHookDllModule);
	return pRemoteData->dwLastError;
}


void* LoadHookDll_End(void)
{
	return LoadHookDll;
}

#define PXCH_ENTRY_DETOUR_TESTING 0
void __cdecl EntryDetour(void)
{
	PXCH_UINT_MACHINE pStartMarker = PXCH_POINTER_PLACEHOLDER_STARTMARKER;
	PXCH_INJECT_REMOTE_DATA* pRemoteData = (void*)PXCH_POINTER_PLACEHOLDER_PREMOTEDATA;
	register PXCH_UINT_MACHINE pReturnAddr;

	(void)pStartMarker;

	// MSVC ignores /Oy- (do not omit frame pointers), so we should call _alloca in it
#ifndef __CYGWIN__
	if (0)
		_alloca(0x20);
#endif

#if PXCH_ENTRY_DETOUR_TESTING
	CAST_FUNC_ADDR(Sleep)(1000);
#else
	HMODULE hHookDllModule;
	FARPROC fpInitFunc;
	LPVOID pbCurrentlyInWinapiCall;
	HANDLE hSemaphore1;
	HANDLE hSemaphore2;
	BOOL bReturn;
	DWORD dwWaitResult;

	DBGSTEP('A');

	pRemoteData->dwEverExecuted = 1;

	DBGSTEP('B');


	DBGSTEP('C');

#ifdef PXCH_MINHOOK_USE_DYNAMIC
	{
		HMODULE hMinHookDllModule = NULL;

		if (pRemoteData->pxchConfig.szMinHookDllPath[0] != L'\0') {
			hMinHookDllModule = CAST_FUNC_ADDR(LoadLibraryW)(pRemoteData->pxchConfig.szMinHookDllPath);
			if (!hMinHookDllModule) {
				pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
				return pRemoteData->dwLastError;
			}
		}
	}
#endif
	
	DBGSTEP('D');

	// ???
	// hHookDllModule = CAST_FUNC_ADDR(GetModuleHandleW)(pRemoteData->szHookDllModuleName);
	// if (hHookDllModule) {
	// 	pRemoteData->dwLastError = ERROR_ALREADY_REGISTERED;
	// 	return ERROR_ALREADY_REGISTERED;
	// }

	DBGSTEP('E');

	pRemoteData->dwLastError = ERROR_DLL_INIT_FAILED;

	hHookDllModule = CAST_FUNC_ADDR(LoadLibraryW)(pRemoteData->pxchConfig.szHookDllPath);
	if (!hHookDllModule) {
		pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
		goto end;
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

	pRemoteData->dwLastError = ERROR_FUNCTION_FAILED;
	pRemoteData->dwLastError = ((DWORD(__stdcall*)(PXCH_INJECT_REMOTE_DATA*))fpInitFunc)(pRemoteData);

	DBGSTEP('I');

	if (pRemoteData->dwLastError != NO_ERROR) goto err_init_func_failed;

	DBGSTEP('J');

	pRemoteData->dwLastError = 0;
	*(BOOL*)pbCurrentlyInWinapiCall = FALSE;

	DBGSTEP('K');

	goto end;

err_init_func_failed:
	goto err_after_load_dll;

err_getprocaddress:
	pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
	goto err_after_load_dll;

err_after_load_dll:
	CAST_FUNC_ADDR(FreeLibrary)(hHookDllModule);
	goto end;

end:
	hSemaphore1 = (HANDLE)(uintptr_t)pRemoteData->qwSemaphore1;
	bReturn = CAST_FUNC_ADDR(ReleaseSemaphore)(hSemaphore1, 1, NULL);
	DBGSTEP('L' + bReturn);
	if (!bReturn) {
		pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
		goto real_end;
	}
	bReturn = CAST_FUNC_ADDR(CloseHandle)(hSemaphore1);
	DBGSTEP('N' + bReturn);
	if (!bReturn) {
		pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
		goto real_end;
	}

real_end:
	hSemaphore2 = (HANDLE)(uintptr_t)pRemoteData->qwSemaphore2;

	dwWaitResult = CAST_FUNC_ADDR(WaitForSingleObject)(hSemaphore2, 3000);
	switch (dwWaitResult)
	{
	case WAIT_OBJECT_0:
		if (!CAST_FUNC_ADDR(ReleaseSemaphore)(hSemaphore2, 1, NULL)) {
			pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
		}
		break;

	case WAIT_ABANDONED:
		pRemoteData->dwLastError = ERROR_ABANDONED_WAIT_0;
		break;

	case WAIT_TIMEOUT:
		pRemoteData->dwLastError = ERROR_TIMEOUT;
		break;

	default:
		pRemoteData->dwLastError = CAST_FUNC_ADDR(GetLastError)();
		break;
	}

	DBGSTEP('P');

	bReturn = CAST_FUNC_ADDR(CloseHandle)(hSemaphore2);

	DBGSTEP('Q' + bReturn);

	// Set strace._active = 1
	// *(unsigned char*)(uintptr_t)(0x1802600a0) = 1;

	// Force schedule ?
	// CAST_FUNC_ADDR(Sleep)(10);

#endif

	pReturnAddr = 0;
	pReturnAddr = pRemoteData->dwZero | PXCH_POINTER_PLACEHOLDER_PRETURNADDR;
	pRemoteData->dwTemp = (PXCH_UINT32)(uint64_t)pReturnAddr;
}


void* EntryDetour_End(void)
{
	return EntryDetour;
}