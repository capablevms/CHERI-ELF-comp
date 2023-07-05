#include <assert.h>
#include <stdlib.h>

int
check_fn(int one, char two, long three)
{
    assert(400 + ('2' - '0') + (double) 0.69 == 402.69);
    assert(one + (two - '0') + three == 422);
    return 0;
}

int
main(int argc, char** argv)
{
    // Don't expect to call this (for now)
    assert(0 && "Why are we here?");
    return 0;
}
