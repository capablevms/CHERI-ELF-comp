#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static void
handler(int sig)
{
    printf("Caught SIGPROT - %d\n", sig);
    exit(0);
}

int
main(void)
{
    signal(SIGPROT, handler);
    char *ptr;
    asm("mrs c4, DDC\n\t"
        "add %[ptr], x4, 0x900000"
        : [ptr] "=r"(ptr)
        :
        : "x4");
    printf("CHAR %c\n", *ptr);
    return 0;
}
