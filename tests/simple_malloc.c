#include <stdlib.h>
#include <string.h>

int
main(void)
{
    const char *hw = "Hello World!";
    char *x = malloc(strlen(hw));
    strcpy(x, hw);
    free(x);
    return 0;
}
