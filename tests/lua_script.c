#include <assert.h>
#include <string.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

int
main(int argc, char** argv)
{
    /*assert(argc == 2);*/
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);

    /*luaL_dofile(L, argv[1]);*/
    luaL_dofile(L, "./hello_world.lua");

    lua_close(L);
    return 0;
}

