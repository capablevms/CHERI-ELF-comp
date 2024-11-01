#include <stdio.h>
#include <unistd.h>

int
main(void)
{
    FILE *my_stdout = fdopen(STDOUT_FILENO, "w");
    const char *hw = "Hello World!";
    fprintf(my_stdout, "Inside - %s\n", hw);
    fclose(my_stdout);
    return 0;
}
