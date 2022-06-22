#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

int
main(void)
{
    lua_State* L = luaL_newstate();
    luaL_openlibs(L);

    lua_pushstring(L, "Hello welt!");
    lua_Integer len = luaL_len(L, 1);

    lua_close(L);
    return len;
}
