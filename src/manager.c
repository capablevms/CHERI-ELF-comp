#include "manager.h"

const char* comp_env_fields[] = { "PATH", };
void* __capability comp_return_caps[COMP_RETURN_CAPS_COUNT];
void* __capability manager_ddc = NULL;
struct Compartment* loaded_comp = NULL; // TODO
struct func_intercept comp_intercept_funcs[INTERCEPT_FUNC_COUNT];

const char*
get_env_str(const char* env_name)
{
    size_t env_name_len = strlen(env_name);
    for (char** env = environ; env != NULL; ++env) {
        const char* str = *env;
        if (strncmp(str, env_name, env_name_len) == 0 && str[env_name_len] == '=')
            return str;
    }
    return NULL;
}

/*******************************************************************************
 * Intercept functions
 ******************************************************************************/

time_t
manager_time(time_t* t)
{
    return time(t);
}

void*
my_realloc(void* ptr, size_t to_alloc)
{
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get());

    if (ptr == NULL)
    {
        return my_malloc(to_alloc); // TODO
    }

    manager_free_mem_alloc(comp, ptr);
    return manager_register_mem_alloc(comp, to_alloc);
}

void*
my_malloc(size_t to_alloc)
{
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get());
    assert(comp->scratch_mem_alloc + to_alloc < comp->scratch_mem_size);
    void* new_mem = manager_register_mem_alloc(comp, to_alloc);
    comp->scratch_mem_alloc += to_alloc;
    return new_mem;
}

void
my_free(void* ptr)
{
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get());
    manager_free_mem_alloc(comp, ptr); // TODO
    return;
}

/*******************************************************************************
 * Utility functions
 ******************************************************************************/

void print_full_cap(uintcap_t cap) {
    uint32_t words[4];  // Hack to demonstrate! In real code, be more careful about sizes, etc.
    printf("0x%d", cheri_tag_get(cap) ? 1 : 0);
    memcpy(words, &cap, sizeof(cap));
    for (int i = 3; i >= 0; i--) {
        printf("_%08x", words[i]);
    }
    printf("\n");
}

/* Setup required capabilities on the heap to jump from within compartments via
 * a context switch
 */
void
setup_intercepts()
{
    for (size_t i = 0; i < sizeof(to_intercept_funcs) / sizeof(to_intercept_funcs[0]); ++i)
    {
        comp_intercept_funcs[i].func_name = to_intercept_funcs[i].func_name;
        comp_intercept_funcs[i].redirect_func = to_intercept_funcs[i].redirect_func;
        comp_intercept_funcs[i].intercept_ddc = manager_ddc;
        comp_intercept_funcs[i].intercept_pcc = cheri_address_set(cheri_pcc_get(), (uintptr_t) intercept_wrapper);
        comp_intercept_funcs[i].redirect_cap = cheri_address_set(manager_ddc, (uintptr_t) &comp_intercept_funcs[i].intercept_ddc);
        print_full_cap((uintcap_t) comp_intercept_funcs[i].redirect_cap);
    }
    comp_return_caps[0] = manager_ddc;
    comp_return_caps[1] = cheri_address_set(cheri_pcc_get(), (uintptr_t) comp_exec_out);
}

struct Compartment*
manager_find_compartment_by_addr(void* ptr)
{
    return loaded_comp; // TODO
}

struct Compartment*
manager_find_compartment_by_ddc(void* __capability ddc)
{
    return loaded_comp; // TODO
}
