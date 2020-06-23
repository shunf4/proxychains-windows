#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <spawn.h>
#include <process.h>
#include <sys/wait.h>
#include <signal.h>
#include <locale.h>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinDef.h>

int main(int argc, char*const*const argv, char*const*const envp)
{
	pid_t child_pid;
	int ret;
	char *const argv_command[] = { "/bin/echo", "你好" };
	BOOL (WINAPI *WriteFunc)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

	//setlocale(LC_ALL, "");
	printf("哈啰\n");
	
	DWORD cbWritten;

	// WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "a", 1, &cbWritten, NULL);
    WriteFunc = (void*)0x7FF8A2212500;
	WriteFunc(GetStdHandle(STD_OUTPUT_HANDLE), "z", 1, &cbWritten, NULL);
	FlushFileBuffers(GetStdHandle(STD_OUTPUT_HANDLE));
	// WriteFile(GetStdHandle(STD_ERROR_HANDLE), "b", 1, &cbWritten, NULL);
	// FlushFileBuffers(GetStdHandle(STD_ERROR_HANDLE));

	printf("米粉\n");
	exit(0);
}
