#include <stdlib.h>
#include <string.h>

static const char *hw = "Hello World!";

void
do_print(const char *const to_print)
{
    printf("Doing print: %s", to_print);
}

int
main(void)
{
    char *x = malloc(strlen(hw));
    strcpy(x, hw);
    do_print(x);
    free(x);
    return 0;
}
