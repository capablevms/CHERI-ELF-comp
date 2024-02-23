#include <dlfcn.h>
#include <err.h>

#include <assert.h>
#include <stdio.h>

int
main(int argc, char **argv)
{
    if (argc != 2)
    {
        errx(1, "Expected one argument - path to `so` file to wrap.\n");
    }
    void *handle = dlopen(argv[1], RTLD_LAZY);
    if (!handle)
    {
        errx(1, "`dlopen` error: %s\n", dlerror());
    }

    dlerror();
    void (*handle_main)() = (void (*)(void)) dlsym(handle, "main");
    char *sym_err = dlerror();
    if (sym_err)
    {
        errx(1, "`dlsym` error: %s\n", sym_err);
    }

    handle_main();

    dlclose(handle);
    return 0;
}
