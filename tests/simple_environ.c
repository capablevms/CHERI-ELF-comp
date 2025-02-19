#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern char **environ;

int
main(void)
{
    size_t i = 0;
    for (char **curr_env = environ; *curr_env; ++curr_env)
    {
        printf("ENV -- %s\n", *curr_env);
        ++i;
    }
    printf("---- COUNT - %zu\n", i);

    char *lang = getenv("LANG");
    assert(lang);
    printf("getenv -- environ['LANG'] == %s\n", lang);

    char *term = getenv("TERM");
    assert(term);
    printf("getenv -- environ['TERM'] == %s\n", term);

    char *no = getenv("DOESNTEXIST");
    assert(no == NULL);

    const char *set_name = "TRYENV";
    const char *set_val = "Hello Env";
    int set_check = setenv(set_name, set_val, 1);
    assert(set_check == 0);
    char *set_get = getenv(set_name);
    printf("setenv -- environ['%s'] == %s\n", set_name, set_get);
    assert(!strcmp(set_get, set_val));

    set_check = putenv("TRYENV=Goodbye Env");
    assert(set_check == 0);
    set_get = getenv(set_name);
    printf("putenv -- environ['%s'] == %s\n", set_name, set_get);
    assert(!strcmp(set_get, "Goodbye Env"));

    return 0;
}
