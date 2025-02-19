#include <assert.h>
#include <limits.h>

_Thread_local int val;
_Thread_local static int val2 = 4242;
_Thread_local static int val3 = INT_MAX;
_Thread_local static long val4 = LONG_MAX;
_Thread_local long val5;

int
get_ext(void);
int
get_ext_stat(void);
void
use_val(void);
void
do_ext_check(int);

int
do_val2(void)
{
    assert(val2 == 4242);
    return val2;
}

int
main(void)
{
    val = 42;
    int i = do_val2();
    assert(val == 42);
    assert(i == 4242);
    assert(val3 == INT_MAX);
    long v4_local = val4;
    assert(v4_local == LONG_MAX);
    val5 = 21;
    assert(val5 * 2 == val);

    // Check external library functions
    assert(get_ext() == 420);
    assert(get_ext_stat() == 242);
    do_ext_check(242);
    use_val();

    return 0;
}
