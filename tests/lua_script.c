#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

static void
handler(int sig)
{
    printf("Caught SIGPROT - %d\n", sig);
    exit(0);
}

int
do_script_arg(char *script_path)
{
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    luaL_dofile(L, script_path);

    lua_close(L);
    return 0;
}

int
do_script_hello(void)
{
    return do_script_arg("./hello_world.lua");
}

int
do_script_memtest(void)
{
    signal(SIGPROT, handler);
    return do_script_arg("./memtest.lua");
}

int
main(void)
{
    do_script_arg("./hello_world.lua");
    return 0;
}
