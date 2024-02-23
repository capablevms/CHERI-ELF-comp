#include <unistd.h>
#include <string.h>
#include <err.h>

int
main(void)
{
    char* buf = "Hello World!\n";
    long int sc_write = syscall(4, STDOUT_FILENO, buf, strlen(buf));
    if (sc_write == -1)
    {
        err(1, "Error calling `syscall`:");
    }
    return 0;
}

