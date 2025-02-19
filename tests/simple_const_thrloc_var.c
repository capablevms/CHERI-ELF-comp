#include <stdio.h>

_Thread_local const int *var;

int
main(void)
{
    int v = 42;
    var = &v;
    printf("PTR -- %p == VAR -- %d\n", (void *) var, *var);
    return 0;
}
