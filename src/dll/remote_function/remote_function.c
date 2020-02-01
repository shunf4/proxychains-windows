#include "stdafx.h"
#include "pxch_defines.h"
#include "pxch_hook.h"
#include "remote.h"

DWORD __stdcall LoadHookDll(LPVOID* pArg)
{
	// Arrays are not allowed here
	INJECT_REMOTE_DATA* pRemoteData = (INJECT_REMOTE_DATA*)pArg;
	HMODULE hHookDllModule;
	HMODULE hMinHookDllModule = NULL;
	FARPROC fpInitFunc;
	FARPROC fpSetCurrentlyInWinapiCall;

#if defined(__CYGWIN__) && 0
	return 0;
#endif

	DBGCHR('A');

	if (pRemoteData->uStructSize != sizeof(INJECT_REMOTE_DATA)) {
		return ERROR_INCORRECT_SIZE;
	}
	pRemoteData->uEverExecuted = 1;

	DBGCHR('B');

	do {
		HMODULE hCygwinModule;

		hCygwinModule = pRemoteData->fpGetModuleHandleW(pRemoteData->szCygwin1ModuleName);
		if (hCygwinModule && PXCHDLL_NOT_SUPPORTING_CYGWIN) {
			pRemoteData->dwErrorCode = ERROR_NOT_SUPPORTED;
			return ERROR_NOT_SUPPORTED;
		}
	} while (0);

	DBGCHR('C');

	if (pRemoteData->pxchConfig.szMinHookDllPath[0] != L'\0') {
		hMinHookDllModule = pRemoteData->fpLoadLibraryW(pRemoteData->pxchConfig.szMinHookDllPath);
		if (!hMinHookDllModule) {
			pRemoteData->dwErrorCode = pRemoteData->fpGetLastError();
			return pRemoteData->dwErrorCode;
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
	fpSetCurrentlyInWinapiCall = pRemoteData->fpGetProcAddress(hHookDllModule, pRemoteData->szCIWCVarName);
	if (!fpSetCurrentlyInWinapiCall) goto err_getprocaddress;
	*(BOOL*)fpSetCurrentlyInWinapiCall = TRUE;

	DBGCHR('G');

	pRemoteData->dwErrorCode = ERROR_PROC_NOT_FOUND;
	fpInitFunc = pRemoteData->fpGetProcAddress(hHookDllModule, pRemoteData->szInitFuncName);
	if (!fpInitFunc) goto err_getprocaddress;

	DBGCHR('H');

	pRemoteData->dwErrorCode = ERROR_FUNCTION_FAILED;
	pRemoteData->dwErrorCode = ((DWORD(__stdcall*)(INJECT_REMOTE_DATA*))fpInitFunc)(pRemoteData);
	
	DBGCHR('I');

	if (pRemoteData->dwErrorCode != NO_ERROR) goto err_init_func_failed;

	DBGCHR('J');

	pRemoteData->dwErrorCode = 0;
	*(BOOL*)fpSetCurrentlyInWinapiCall = FALSE;

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