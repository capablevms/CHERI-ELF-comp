#include <assert.h>
#include <limits.h>
#include <stdlib.h>

int
check_long(long long one)
{
    assert(one == LLONG_MAX);
    return 0;
}

int
main()
{
    // Don't expect to call this (for now)
    assert(0 && "Why are we here?");
    return 0;
}
