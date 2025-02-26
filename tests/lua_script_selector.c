#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

const unsigned int max_path_sz = 256;
const char *test_dir = "./lua";
const char *test_names[] = {
    "bench-binarytrees.lua",
    "bench2-binarytrees.lua",
    "bench2-fannkuchredux.lua",
    "bench2-heapsort.lua",
    "bench2-nbody.lua",
    "bench2-sieve.lua",
    "hello_world.lua",
    "math.lua",
    "tracegc.lua",
};

int
do_script_id(const unsigned int test_id)
{
    char test_path[max_path_sz];
    snprintf(
        test_path, sizeof(test_path), "%s/%s", test_dir, test_names[test_id]);
    if (access(test_path, F_OK) != 0)
    {
        errx(1, "Could not find test file `%s` for ID %d!", test_path, test_id);
    }

    printf("Running test ID %u at `%s`\n", test_id, test_path);

    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
    int res = luaL_dofile(L, test_path);
    lua_close(L);

    if (res != LUA_OK)
    {
        errx(1, "Error running test `%s`!", test_path);
    }

    printf("Done\n");

    return 0;
}

int
main(int argc, char **argv)
{
    if (argc != 2)
    {
        errx(1, "Expected exactly one argument: identifier of test to run!");
    }

    unsigned int test_id = atoi(argv[1]);
    const unsigned int test_count = sizeof(test_names) / sizeof(char *);
    if (test_id >= test_count)
    {
        errx(1, "Was given ID %d, but only %u tests available!", test_id,
            test_count);
    }

    do_script_id(test_id);

    return 0;
}
