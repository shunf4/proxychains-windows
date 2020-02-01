#include "stdafx.h"
#include "pxch_defines.h"
#include "pxch_hook.h"

// #define PXCHDEBUG_REMOTEFUNCTION

DWORD __stdcall LoadHookDll(LPVOID* pArg)
{
	// Arrays are not allowed here
	INJECT_REMOTE_DATA* pRemoteData = (INJECT_REMOTE_DATA*)pArg;
	HMODULE hHookDllModule;
	HMODULE hMinHookDllModule = NULL;
	FARPROC fpInitFunc;
	FARPROC fpSetCurrentlyInWinapiCall;
#ifdef PXCHDEBUG_REMOTEFUNCTION
	char* pDebugOutput = pRemoteData->chDebugOutput;
#endif

#if defined(__CYGWIN__) && 0
	return 0;
#endif

#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('A' - 'A') * 2); // A
#endif

	if (pRemoteData->uStructSize != sizeof(INJECT_REMOTE_DATA)) {
		return ERROR_INCORRECT_SIZE;
	}
	pRemoteData->uEverExecuted = 1;

#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('B' - 'A') * 2);
#endif

	do {
		HMODULE hCygwinModule;

		hCygwinModule = pRemoteData->fpGetModuleHandleW(pRemoteData->szCygwin1ModuleName);
		if (hCygwinModule && PXCHDLL_NOT_SUPPORTING_CYGWIN) {
			pRemoteData->dwErrorCode = ERROR_NOT_SUPPORTED;
			return ERROR_NOT_SUPPORTED;
		}
	} while (0);

#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('C' - 'A') * 2);
#endif

	if (pRemoteData->pxchConfig.szMinHookDllPath[0] != L'\0') {
		hMinHookDllModule = pRemoteData->fpLoadLibraryW(pRemoteData->pxchConfig.szMinHookDllPath);
		if (!hMinHookDllModule) {
			pRemoteData->dwErrorCode = pRemoteData->fpGetLastError();
			return pRemoteData->dwErrorCode;
		}
	}

#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('D' - 'A') * 2);
#endif

	hHookDllModule = pRemoteData->fpGetModuleHandleW(pRemoteData->szHookDllModuleName);
	if (hHookDllModule) {
		pRemoteData->dwErrorCode = ERROR_ALREADY_REGISTERED;
		return ERROR_ALREADY_REGISTERED;
	}

#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('E' - 'A') * 2);
#endif

	pRemoteData->dwErrorCode = ERROR_DLL_INIT_FAILED;

	hHookDllModule = pRemoteData->fpLoadLibraryW(pRemoteData->pxchConfig.szHookDllPath);
	if (!hHookDllModule) {
		pRemoteData->dwErrorCode = pRemoteData->fpGetLastError();
		return pRemoteData->dwErrorCode;
	}

#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('F' - 'A') * 2);
#endif

	pRemoteData->dwErrorCode = ERROR_PROC_NOT_FOUND;
	fpSetCurrentlyInWinapiCall = pRemoteData->fpGetProcAddress(hHookDllModule, pRemoteData->szCIWCVarName);
	if (!fpSetCurrentlyInWinapiCall) goto err_getprocaddress;
	*(BOOL*)fpSetCurrentlyInWinapiCall = TRUE;

#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('G' - 'A') * 2);
#endif

	pRemoteData->dwErrorCode = ERROR_PROC_NOT_FOUND;
	fpInitFunc = pRemoteData->fpGetProcAddress(hHookDllModule, pRemoteData->szInitFuncName);
	if (!fpInitFunc) goto err_getprocaddress;

#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('H' - 'A') * 2);
#endif

	pRemoteData->dwErrorCode = ERROR_FUNCTION_FAILED;
	pRemoteData->dwErrorCode = ((DWORD(__stdcall*)(INJECT_REMOTE_DATA*))fpInitFunc)(pRemoteData);
	
#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('I' - 'A') * 2);
#endif

	if (pRemoteData->dwErrorCode != NO_ERROR) goto err_init_func_failed;

#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('J' - 'A') * 2);
#endif

	pRemoteData->dwErrorCode = 0;
	*(BOOL*)fpSetCurrentlyInWinapiCall = FALSE;

#ifdef PXCHDEBUG_REMOTEFUNCTION
	pRemoteData->fpOutputDebugStringA(pDebugOutput + ('K' - 'A') * 2);
#endif
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