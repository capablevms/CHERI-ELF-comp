#include "manager.h"

const char* comp_env_fields[] = { "PATH", };
void* __capability manager_ddc = NULL;
struct Compartment* loaded_comp = NULL; // TODO

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
