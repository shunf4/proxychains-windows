#include <stdio.h>
#include <unistd.h>

int main(int argc, char*const*const argv, char*const*const envp)
{
	printf("I'm test2 pid %d\n", getpid());
	return 0;
}
