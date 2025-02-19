#include <assert.h>

extern _Thread_local int v;
extern _Thread_local int v2;

int
main(void)
{
    v = 42;
    v2 = 84;
    assert(v == 42);
    return (v - 42);
}
