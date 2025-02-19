#include <assert.h>

_Thread_local int ex_val;
_Thread_local int ex_val_used;
_Thread_local static int ex_val_stat = 242;
_Thread_local int from_int;

int
get_ext(void)
{
    ex_val = 420;
    return ex_val;
}

int
get_ext_stat(void)
{
    return ex_val_stat;
}

void
use_val(void)
{
    ex_val_used = 24;
    assert(ex_val_used == 24);
}

void
do_ext_check(int val)
{
    from_int = val;
    assert(from_int == ex_val_stat);
}
