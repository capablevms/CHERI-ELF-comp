#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

int
main(void)
{
    const char *test_dir = "./lua";
    const char *test_names[] = { "strings.lua", "utf8.lua", "goto.lua",
        "tpack.lua", "tracegc.lua", "calls.lua" };
    // TODO disabled due to extremely long runtime; needs profiling
    /*const char *test_names[] = { "gc.lua" };*/

    /* `lua_dofile` not returning `LUA_OK`, even without compartmentalisation
     * api.lua
     * attrib.lua
     * big.lua
     * cstack.lua
     */

    /* Internally skipped tests (needs additional testing infrastructure support
     * for `lua`) api.c
     */

    lua_State *L = luaL_newstate();
    luaL_openlibs(L);

    char buf[256];
    for (size_t i = 0; i < sizeof(test_names) / sizeof(test_names[0]); ++i)
    {
        snprintf(buf, sizeof(buf), "%s/%s", test_dir, test_names[i]);
        printf(" == Running `%s`\n", buf);
        assert(access(buf, F_OK) == 0);
        assert(luaL_dofile(L, buf) == LUA_OK);
    }

    lua_close(L);

    return 0;
}
