#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(void)
{
    char *buf = "Hello File!\n";
    char *file = "out_syscall_write";
    int fd = open(file, O_WRONLY | O_CREAT);
    if (fd == -1)
    {
        err(1, "Error in open: ");
    }
    if (write(fd, buf, strlen(buf)) == -1)
    {
        err(1, "Error in write: ");
    }
    if (close(fd) == -1)
    {
        err(1, "Error in close: ");
    }
    return 0;
}
