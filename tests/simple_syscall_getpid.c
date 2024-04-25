#include <assert.h>
#include <sys/syscall.h>
#include <unistd.h>

int
main(void)
{
    long int sc_pid = syscall(SYS_getpid);
    pid_t pid = getpid();
    assert(pid == sc_pid);
    return 0;
}
