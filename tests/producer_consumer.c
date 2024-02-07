#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cheriintrin.h>

#include "producer_consumer_mem.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

// Simplified memory model: stk grows downwards from the top
//
struct comp
{
    size_t size;
    void *__capability ddc;
    uintptr_t sp;
};

void *__capability big_ddc;
void *saved_sp;

const size_t mem_size = 256;
const size_t max_comp_count = 2;
size_t comp_count = 0;
struct comp comps[max_comp_count];

#define PROD_CAP_OFFSET 0
#define CONS_CAP_OFFSET 1

void
print_full_cap(uintcap_t cap)
{
    uint32_t words[4]; // Hack to demonstrate! In real code, be more careful
                       // about sizes, etc.
    printf("0x%d", cheri_tag_get(cap) ? 1 : 0);
    memcpy(words, &cap, sizeof(cap));
    for (int i = 3; i >= 0; i--)
    {
        printf("_%08x", words[i]);
    }
    printf("\n");
}

int
producer_func(lua_State *L)
{
    /*asm("msr DDC, %w0" : : "r"(prod_ddc));*/

    lua_getglobal(L, "producer");
    lua_call(L, 0, 1);
    int val = lua_tonumber(L, -1);
    lua_pushnumber(L, val);

    /*asm("msr DDC, %w0" : : "r"(big_ddc));*/

    return 1;
}

int
consumer_func(int val)
{
    return val % 5;
}

struct comp
make_new_comp(size_t size)
{
    /*void* new_comp_mem = mmap(NULL, size,*/
    /*PROT_READ | PROT_WRITE,*/
    /*MAP_PRIVATE | MAP_ANONYMOUS,*/
    /*-1 , 0)*/

    void *__capability new_ddc = (void *__capability) malloc(size);
    new_ddc = cheri_bounds_set(new_ddc, size);

    struct comp new_comp;
    new_comp.size = size;
    new_comp.ddc = new_ddc;

    uintptr_t ddc_addr = cheri_address_get(new_ddc);
    new_comp.sp = ddc_addr + size + COMP_STK_OFFSET;
    int *alloc_mem_addr = (int *) (ddc_addr + size + COMP_MEM_DDC_OFFSET);
    *alloc_mem_addr = 0;

    void *__capability *big_ddc_addr
        = (void *__capability *) (ddc_addr + size + COMP_BIG_DDC_OFFSET);

    assert(new_comp.sp % 16 == 0);
    assert((uintptr_t) alloc_mem_addr % 16 == 0);

    comp_count += 1;
    assert(comp_count <= max_comp_count);

    return new_comp;
}

int
main(void)
{
    big_ddc = cheri_ddc_get();
    comps[PROD_CAP_OFFSET] = make_new_comp(4096);
    comps[CONS_CAP_OFFSET] = make_new_comp(4096);

    /*void* tmp = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE |
     * MAP_ANONYMOUS, -1, 0);*/
    /*if (tmp == MAP_FAILED)*/
    /*{*/
    /*printf("Error %s\n", strerror(errno));*/
    /*assert(0);*/
    /*}*/
    /*assert(munmap(tmp, 1024) != -1);*/

    asm("mov %[saved_sp], sp\n\t" : [saved_sp] "+r"(saved_sp) : /**/);

    // Set consumer compartment
    asm("msr DDC, %[cons_ddc]\n\t"
        "mov sp, %[cons_sp]"
        : /**/
        : [cons_ddc] "C"(comps[CONS_CAP_OFFSET].ddc),
        [cons_sp] "r"(comps[CONS_CAP_OFFSET].sp));

    lua_State *consumerL = luaL_newstate();
    luaL_openlibs(consumerL);

    /*lua_pushcfunction(L, producer_func);*/
    /*lua_setglobal(L, "prod_fn");*/

    luaL_dofile(consumerL, "producer_consumer.lua");
    lua_getglobal(consumerL, "consumer");
    lua_call(consumerL, 0, 1);
    int val = lua_tonumber(consumerL, -1);
    printf("val is %d\n", val);
    lua_pop(consumerL, 1);

    lua_close(consumerL);
    asm("msr DDC, %[big_ddc]\n\t"
        "mov sp, %[saved_sp]\n\t"
        :
        : [big_ddc] "C"(big_ddc), [saved_sp] "r"(saved_sp));

    return EXIT_SUCCESS;
}
