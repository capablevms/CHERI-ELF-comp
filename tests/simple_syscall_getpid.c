#include <assert.h>
#include <unistd.h>

int
main(void)
{
    long int sc_pid = syscall(20);
    pid_t pid = getpid();
    assert(pid == sc_pid);
    return 0;
}
