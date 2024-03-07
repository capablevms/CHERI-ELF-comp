#include <assert.h>
#include <math.h>

int __attribute__((weak)) call_internal(int x) { return pow(x, 2); }

int
main(void)
{
    int val = 4;
    assert(val * val == call_internal(val));
    return 0;
}
