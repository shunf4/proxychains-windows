#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <spawn.h>
#include <sys/wait.h>

void handle_sigchld(int sig)
{
	while (waitpid((pid_t)(-1), 0, WNOHANG) > 0) {}
	printf("Child Process Terminated.");
	exit(0);
}

void handle_sigint(int sig)
{
	//printf("[PX:Ctrl-C]");
	//fflush(stdout);
}

int main(int argc, char*const*const argv, char*const*const envp)
{
	int ret;
	pid_t child_pid;

	signal(SIGINT, handle_sigint);
	signal(SIGCHLD, handle_sigchld);

	ret = posix_spawnp(&child_pid, argv[1], NULL, NULL, &argv[1], envp);
	printf("spawn ret: %d; pid: %d\n", ret, child_pid);
	// waitpid(-1, &ret, 0);
	// printf("waitpid() ends\n");
	pause();
	printf("pause() ends\n");
	return 0;
}