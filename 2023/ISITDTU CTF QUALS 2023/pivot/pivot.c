// sudo apt-get install libseccomp-dev
// gcc pivot.c -o pivot -fno-stack-protector -no-pie -s -lseccomp 
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <seccomp.h>


void init_seccomp()
{
    scmp_filter_ctx ctx = NULL;
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL)
    {
        {
            printf("seccomp error\\n");
            exit(0);
        }
    }
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(kill), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(tkill), 0);
    seccomp_load(ctx);
}

void timeout()
{
    exit(1);
}

void setup()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    signal(SIGALRM, timeout);
    alarm(60);
}
int main()
{
    int (*ret)();
    char *addr;
    addr = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
    setup();
    init_seccomp();
    puts("Blacklist: execve, execveat, kill, tkill\nFind flag");
    read(0, addr, 0x1000);
    ret = addr;
    ret();
    return 0;
}