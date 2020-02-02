#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>

void handle_sigint(int sig)
{
	printf("[Ctrl-C]");
	fflush(stdout);
}

int main(int argc, char*const*const argv, char*const*const envp)
{
    int ret;
    pid_t child_pid;

    signal(SIGINT, handle_sigint);

    connect

    pause();
    return 0;
}