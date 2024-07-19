#include <assert.h>
#include <math.h>

extern const int val;

int
call_external(int);

int
main(void)
{
    assert(val == call_external(val));
    return 0;
}
