#include <stdio.h>
#include <unistd.h>

int
main()
{
    /*FILE* strem = __stdoutp;*/
    FILE *strem = fdopen(STDOUT_FILENO, "w");
    fputs("Hello\n", strem);
    fclose(strem);
    return 0;
}
