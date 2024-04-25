#include <err.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int
main(void)
{
    char *buf = "Hello World!\n";
    long int sc_write = syscall(SYS_write, STDOUT_FILENO, buf, strlen(buf));
    if (sc_write == -1)
    {
        err(1, "Error calling `syscall`:");
    }
    return 0;
}
