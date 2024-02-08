#include <assert.h>
#include <math.h>

int
call_external(int);

int
main(void)
{
    int val = 4;
    assert(val == call_external(val));
    return 0;
}
