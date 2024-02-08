#include <assert.h>
#include <limits.h>
#include <stdlib.h>

int
check_combined(int one, char two, long three)
{
    assert(400 + ('2' - '0') + (double) 0.69 == 402.69);
    assert(one + (two - '0') + three == 422);
    return 0;
}

int
check_simple(int one, int two)
{
    assert(one + two == 42);
    return 0;
}

int
check_negative(int one)
{
    assert(one == -42);
    return 0;
}

int
check_llong_max(long long one)
{
    assert(one == LLONG_MAX);
    return 0;
}

int
check_llong_min(long long one)
{
    assert(one == LLONG_MIN);
    return 0;
}

int
check_ullong_max(unsigned long long one)
{
    assert(one == ULLONG_MAX);
    return 0;
}

int
main(int argc, char **argv)
{
    size_t sum = 0;
    for (int i = 0; i < argc; ++i)
    {
        sum += atoi(argv[i]);
    }
    assert(sum == 42);
    return 0;
}
