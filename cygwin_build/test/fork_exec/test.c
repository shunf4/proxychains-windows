#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <spawn.h>
#include <sys/wait.h>

int main(int argc, char*const*const argv, char*const*const envp)
{
    int ret;
    pid_t child_pid;

    child_pid = fork();

    if (child_pid == 0) {
        // Child
        ret = execve(argv[1], argv + 1, envp);
    } else {
        waitpid(-1, &ret, 0);
        printf("waitpid() ends\n");
        return 0;
    }
    return 0;
}