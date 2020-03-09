#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <spawn.h>
#include <process.h>
#include <sys/wait.h>
#include <signal.h>

int main(int argc, char*const*const argv, char*const*const envp)
{
	const char* my_argv[] = {"./_test3", NULL};
	spawnvpe(_P_NOWAIT, "./_test3", my_argv, (const char*const*)envp);
    return 0;
}
