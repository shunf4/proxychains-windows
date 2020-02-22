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
#include "defines_win32.h"
#include "remote_win32.h"

DWORD __stdcall LoadHookDll(LPVOID* pArg)
{
	// Arrays are not allowed here
	PXCH_INJECT_REMOTE_DATA* pRemoteData = (PXCH_INJECT_REMOTE_DATA*)pArg;
	HMODULE hHookDllModule;
	HMODULE hMinHookDllModule = NULL;
	FARPROC fpInitFunc;
	LPVOID pbCurrentlyInWinapiCall;

	DBGCHR('A');

	if (pRemoteData->dwSize != sizeof(PXCH_INJECT_REMOTE_DATA) + PXCH_CONFIG_EXTRA_SIZE(&pRemoteData->pxchConfig)) {
		return ERROR_INCORRECT_SIZE;
	}

	pRemoteData->dwEverExecuted = 1;
	DBGCHR('B');

	
	DBGCHR('C');

	if (pRemoteData->pxchConfig.szMinHookDllPath[0] != L'\0') {
		hMinHookDllModule = ((FpLoadLibraryW)(pRemoteData->fpLoadLibraryW))(pRemoteData->pxchConfig.szMinHookDllPath);
		if (!hMinHookDllModule) {
			// pRemoteData->dwErrorCode = pRemoteData->fpGetLastError();
			// return pRemoteData->dwErrorCode;
		}
	}
	
	DBGCHR('D');

	// ???
	// hHookDllModule = ((FpGetModuleHandleW)(pRemoteData->fpGetModuleHandleW))(pRemoteData->szHookDllModuleName);
	// if (hHookDllModule) {
	// 	pRemoteData->dwErrorCode = ERROR_ALREADY_REGISTERED;
	// 	return ERROR_ALREADY_REGISTERED;
	// }

	DBGCHR('E');

	pRemoteData->dwErrorCode = ERROR_DLL_INIT_FAILED;

	hHookDllModule = ((FpLoadLibraryW)(pRemoteData->fpLoadLibraryW))(pRemoteData->pxchConfig.szHookDllPath);
	if (!hHookDllModule) {
		pRemoteData->dwErrorCode = ((FpGetLastError)(pRemoteData->fpGetLastError))();
		return pRemoteData->dwErrorCode;
	}

	DBGCHR('F');

	pRemoteData->dwErrorCode = ERROR_PROC_NOT_FOUND;
	pbCurrentlyInWinapiCall = ((FpGetProcAddress)(pRemoteData->fpGetProcAddress))(hHookDllModule, pRemoteData->szCIWCVarName);
	if (!pbCurrentlyInWinapiCall) goto err_getprocaddress;
	*(BOOL*)pbCurrentlyInWinapiCall = TRUE;

	DBGCHR('G');

	pRemoteData->dwErrorCode = ERROR_PROC_NOT_FOUND;
	fpInitFunc = ((FpGetProcAddress)(pRemoteData->fpGetProcAddress))(hHookDllModule, pRemoteData->szInitFuncName);
	if (!fpInitFunc) goto err_getprocaddress;

	DBGCHR('H');

	pRemoteData->dwErrorCode = ERROR_FUNCTION_FAILED;
	pRemoteData->dwErrorCode = ((DWORD(__stdcall*)(PXCH_INJECT_REMOTE_DATA*))fpInitFunc)(pRemoteData);
	
	DBGCHR('I');

	if (pRemoteData->dwErrorCode != NO_ERROR) goto err_init_func_failed;

	DBGCHR('J');

	pRemoteData->dwErrorCode = 0;
	*(BOOL*)pbCurrentlyInWinapiCall = FALSE;

	DBGCHR('K');

	return 0;

err_init_func_failed:
	goto err_after_load_dll;

err_getprocaddress:
	pRemoteData->dwErrorCode = ((FpGetLastError)(pRemoteData->fpGetLastError))();
	goto err_after_load_dll;

err_after_load_dll:
	((FpFreeLibrary)(pRemoteData->fpFreeLibrary))(hHookDllModule);
	return pRemoteData->dwErrorCode;
}


void* LoadHookDll_End(void)
{
	return LoadHookDll;
}