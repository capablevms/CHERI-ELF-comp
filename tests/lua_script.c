#include <assert.h>
#include <string.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

int
simple_val()
{
    return 42;
}

int
return_val(int val)
{
    return val;
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
do_script()
{
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    luaL_dofile(L, "./hello_world.lua");

    lua_close(L);
    return 0;
}

int
main(int argc, char **argv)
{
    do_script_arg("./hello_world.lua");
    return 0;
}
