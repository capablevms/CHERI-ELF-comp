#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void
by_fopen()
{
    FILE *fd = fopen("tmp", "w");
    fprintf(fd, "Hi\n");
    fclose(fd);
}

void
by_syscall()
{
}

void
by_open()
{
    int fd = open("tmp", O_WRONLY | O_CREAT);
    if (fd == -1)
    {
        err(1, "Error in open: ");
    }
    char *buf = "Hi\n";
    write(fd, buf, strlen(buf));
    close(fd);
}

int
main()
{
    by_open();
    return 0;
}
