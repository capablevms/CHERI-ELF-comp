#include <assert.h>
#include <stdarg.h>

int
sum(int count, ...)
{
    va_list vals;
    va_start(vals, count);
    int acc = 0;
    int val;
    for (int i = 0; i < count; ++i)
    {
        val = va_arg(vals, int);
        acc += val;
    }
    va_end(vals);
    return acc;
}

int
main()
{
    int suman = sum(3, 15, 30, -3);
    assert(suman == 42);
    return 0;
}
