#pragma once

#include "hookdll_interior_generic.h"

DWORD IpcClientRegisterChildProcess();
PXCH_UINT32 RestoreChildData();

DWORD InjectTargetProcess(const PROCESS_INFORMATION* pPi);

void Win32HookWs2_32(void);
void CygwinHook(void);