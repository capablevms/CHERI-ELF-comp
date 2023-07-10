#include <assert.h>
#include <stdlib.h>

int
check_fn(int one, int two)
{
    assert(one + two == 42);
    return 0;
}

int
main(int argc, char** argv)
{
    size_t sum = 0;
    for (size_t i = 0; i < argc; ++i)
    {
        sum += atoi(argv[i]);
    }
    assert(sum == 42);
    return 0;
}
