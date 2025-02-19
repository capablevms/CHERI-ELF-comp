#include <assert.h>

extern unsigned short fortytwo;

int
main(void)
{
    assert(fortytwo == 42);
    return 0;
}
