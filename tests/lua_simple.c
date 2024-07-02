#include <string.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

int
main(void)
{
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    char *test_string = "Hello welt!";
    lua_pushstring(L, test_string);
    lua_Integer len = luaL_len(L, 1);

    lua_close(L);
    return ((unsigned long) len == strlen(test_string) ? 0 : 1);
}
