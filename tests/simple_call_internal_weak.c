#include <assert.h>
#include <math.h>

// clang-format off: local clang-format seems to have diverged from CHERI one
int __attribute__((weak)) call_internal(int x) { return pow(x, 2); }

// clang-format on

int
main(void)
{
    int val = 4;
    assert(val * val == call_internal(val));
    return 0;
}
