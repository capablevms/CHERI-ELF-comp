#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

void
by_fopen(void)
{
    FILE *fd = fopen("tmp", "w");
    if (!fd)
    {
        err(1, "Error in fopen: ");
    }
    fclose(fd);
}

void
by_syscall(void)
{
    int fd = syscall(SYS_open, "tmp", O_CREAT); // open
    if (fd == -1)
    {
        err(1, "Error in open: ");
    }
    syscall(SYS_close, fd); // close
}

void
by_open(void)
{
    int fd = open("tmp", O_CREAT);
    if (fd == -1)
    {
        err(1, "Error in open: ");
    }
    close(fd);
}

int
main(void)
{
    write(STDOUT_FILENO, "== By open\n", 11);
    by_open();
    write(STDOUT_FILENO, "== By syscall\n", 14);
    by_syscall();
    write(STDOUT_FILENO, "== By fopen\n", 12);
    by_fopen();
    return 0;
}
