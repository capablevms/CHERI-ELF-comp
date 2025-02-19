#include <assert.h>

int
get_ext_val(void);

int
main(void)
{
    int ext_val = get_ext_val();
    assert(ext_val == 42);
    return 0;
}
