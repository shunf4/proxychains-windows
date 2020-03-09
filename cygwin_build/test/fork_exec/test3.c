#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <spawn.h>
#include <sys/wait.h>
#include <signal.h>

int main(int argc, char*const*const argv, char*const*const envp)
{
	pid_t child_pid;
	pid_t pid;
    printf("\e[1;34mhi, my main address %p\e[m\n", &main);
	sleep(60);
    printf("\e[1;34mhi, my pid %d\e[m\n", getpid());
    return 0;
}
