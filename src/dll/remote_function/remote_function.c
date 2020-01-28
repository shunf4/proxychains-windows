#include "stdafx.h"
#include "pxch_defines.h"

DWORD __stdcall LoadHookDll(LPVOID* pArg)
{
	INJECT_REMOTE_DATA* pRemoteData = (INJECT_REMOTE_DATA*)pArg;
	HMODULE hCygwinModule;
	HMODULE hHookDllModule;
	FARPROC pInitFunc;

	if (pRemoteData->uStructSize != sizeof(INJECT_REMOTE_DATA)) {
		return ERROR_INCORRECT_SIZE;
	}
	pRemoteData->uEverExecuted = 1;

	hCygwinModule = pRemoteData->fpGetModuleHandleW(L"cygwin1.dll");
	if (hCygwinModule) {
		pRemoteData->dwErrorCode = ERROR_NOT_SUPPORTED;
		return ERROR_NOT_SUPPORTED;
	}

	hHookDllModule = pRemoteData->fpGetModuleHandleW(szDllFileName);
	if (hHookDllModule) {
		pRemoteData->dwErrorCode = ERROR_ALREADY_REGISTERED;
		return ERROR_ALREADY_REGISTERED;
	}

	pRemoteData->dwErrorCode = ERROR_DLL_INIT_FAILED;
	hHookDllModule = pRemoteData->fpLoadLibraryW(pRemoteData->pxchConfig.szDllPath);
	if (!hHookDllModule) {
		pRemoteData->dwErrorCode = pRemoteData->fpGetLastError();
		return pRemoteData->dwErrorCode;
	}

	pRemoteData->dwErrorCode = ERROR_PROC_NOT_FOUND;
	pInitFunc = pRemoteData->fpGetProcAddress(hHookDllModule, pRemoteData->szInitFuncName);
	if (!pInitFunc) goto err_getprocaddress;

	pRemoteData->dwErrorCode = ERROR_FUNCTION_FAILED;
	pRemoteData->dwErrorCode = ((DWORD(__stdcall*)(INJECT_REMOTE_DATA*))pInitFunc)(pRemoteData);
	if (pRemoteData->dwErrorCode != NO_ERROR) goto err_init_func_failed;

	pRemoteData->dwErrorCode = 0;
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