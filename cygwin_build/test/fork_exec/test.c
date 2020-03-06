#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <spawn.h>
#include <sys/wait.h>
#include <signal.h>

int main(int argc, char*const*const argv, char*const*const envp)
{
    int ret;
    pid_t child_pid;
    int i;

    printf("parent pid %d\n", getpid());
    //sleep(1);

    for (i = 0; i < 1; i++) {
		child_pid = fork();

		if (child_pid == 0) {
			// Child
			ret = execve(argv[1], argv + 1, envp);
		} else {
			waitpid(-1, &ret, 0);
			printf("waitpid() ends\n");
			fflush(stdout);
		}
	}
    return 0;
}
