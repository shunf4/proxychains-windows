#include <SDKDDKVer.h>
#include <stdio.h>
#include <tchar.h>

#include <windows.h>
#include <iostream>

typedef DWORD(WINAPI* fp_NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateSuspended,
    DWORD dwStackSize,
    LPVOID Unknown1,
    LPVOID Unknown2,
    LPVOID Unknown3);

int _tmain(int argc, _TCHAR* argv[])
{
    const char* dllPath = ".\\proxychains_hook.dll";

    void* pLoadLibrary = (void*)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");

    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInformation;

    ZeroMemory(&startupInfo, sizeof(startupInfo));

    // CreateProcessA(0, const_cast<char*>("C:\\Users\\shunf4\\AppData\\Local\\Chromium\\Application\\chrome.exe"), 0, 0, 1, CREATE_NEW_CONSOLE, 0, 0, &startupInfo, &processInformation);
    // CreateProcessA(0, const_cast<char*>("Test.exe"), 0, 0, 1, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, 0, 0, &startupInfo, &processInformation);
    CreateProcessA(0, const_cast<char*>("C:\\cygwin64\\bin\\curl.exe --connect-timeout 10 -4vvvv http://ip.sb"), 0, 0, 1, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, 0, 0, &startupInfo, &processInformation);
    // CreateProcessA(0, const_cast<char*>("test.bat"), 0, 0, 1, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, 0, 0, &startupInfo, &processInformation);
    // CreateProcessA(0, const_cast<char*>("test.bat"), 0, 0, 1, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, 0, 0, &startupInfo, &processInformation);
    // CreateProcessA(0, const_cast<char *>("notepad.exe"), 0, 0, 1, CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, 0, 0, &startupInfo, &processInformation);

    void* pReservedSpace = VirtualAllocEx(processInformation.hProcess, NULL, strlen(dllPath), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(processInformation.hProcess, pReservedSpace, dllPath, strlen(dllPath), NULL);
    printf("xxxx\n");

    HANDLE hThread = NULL;
    fp_NtCreateThreadEx_t fp_NtCreateThreadEx = NULL;
    fp_NtCreateThreadEx = (fp_NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    /*fp_NtCreateThreadEx(
        &hThread,
        0x2000000,
        NULL,
        processInformation.hProcess,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        pReservedSpace,
        FALSE, 0, NULL, NULL, NULL);
    WaitForSingleObject(hThread, INFINITE);*/
    CreateRemoteThread(processInformation.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pReservedSpace, 0, NULL);
    printf("xxx\n");
    VirtualFreeEx(processInformation.hProcess, pReservedSpace, strlen(dllPath), MEM_COMMIT);
    printf("xxxxx\n");

    ResumeThread(processInformation.hThread);
    printf("xxxxxx\n");
    WaitForSingleObject(processInformation.hProcess, INFINITE);

    return 0;
}