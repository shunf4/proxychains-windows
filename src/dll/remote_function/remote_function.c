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

	if (pRemoteData->dwSize != sizeof(PXCH_INJECT_REMOTE_DATA) + PXCHCONFIG_EXTRA_SIZE(&pRemoteData->pxchConfig)) {
		return ERROR_INCORRECT_SIZE;
	}
	pRemoteData->dwEverExecuted = 1;

	DBGCHR('B');

#ifndef __CYGWIN__
	do {
		HMODULE hCygwinModule;

		hCygwinModule = pRemoteData->fpGetModuleHandleW(pRemoteData->szCygwin1ModuleName);
		if (hCygwinModule) {
			pRemoteData->dwErrorCode = ERROR_NOT_SUPPORTED;
			return ERROR_NOT_SUPPORTED;
		}
	} while (0);
#endif

	DBGCHR('C');

	if (pRemoteData->pxchConfig.szMinHookDllPath[0] != L'\0') {
		hMinHookDllModule = pRemoteData->fpLoadLibraryW(pRemoteData->pxchConfig.szMinHookDllPath);
		if (!hMinHookDllModule) {
			// pRemoteData->dwErrorCode = pRemoteData->fpGetLastError();
			// return pRemoteData->dwErrorCode;
		}
	}

	DBGCHR('D');

	hHookDllModule = pRemoteData->fpGetModuleHandleW(pRemoteData->szHookDllModuleName);
	if (hHookDllModule) {
		pRemoteData->dwErrorCode = ERROR_ALREADY_REGISTERED;
		return ERROR_ALREADY_REGISTERED;
	}

	DBGCHR('E');

	pRemoteData->dwErrorCode = ERROR_DLL_INIT_FAILED;

	hHookDllModule = pRemoteData->fpLoadLibraryW(pRemoteData->pxchConfig.szHookDllPath);
	if (!hHookDllModule) {
		pRemoteData->dwErrorCode = pRemoteData->fpGetLastError();
		return pRemoteData->dwErrorCode;
	}

	DBGCHR('F');

	pRemoteData->dwErrorCode = ERROR_PROC_NOT_FOUND;
	pbCurrentlyInWinapiCall = pRemoteData->fpGetProcAddress(hHookDllModule, pRemoteData->szCIWCVarName);
	if (!pbCurrentlyInWinapiCall) goto err_getprocaddress;
	*(BOOL*)pbCurrentlyInWinapiCall = TRUE;

	DBGCHR('G');

	pRemoteData->dwErrorCode = ERROR_PROC_NOT_FOUND;
	fpInitFunc = pRemoteData->fpGetProcAddress(hHookDllModule, pRemoteData->szInitFuncName);
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
	pRemoteData->dwErrorCode = pRemoteData->fpGetLastError();
	goto err_after_load_dll;

err_after_load_dll:
	pRemoteData->fpFreeLibrary(hHookDllModule);
	return pRemoteData->dwErrorCode;
}


void* LoadHookDll_End(void)
{
	return LoadHookDll;
}