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
 *
 * These functions are meant to be executed within a manager context, by
 * intercepting certain functions within compartments which must have higher
 * privlige
 ******************************************************************************/

time_t
manager_time(time_t* t)
{
    return time(t);
}

/* As we are performing data compartmentalization, we must store relevant
 * information for accessing an opened file within compartment memory. However,
 * as we are using a bump allocator for internal memory management, we do not
 * have the capability of `free`ing this memory. A future implementation of a
 * better memory allocator will resolve this issue.
 */
FILE*
manager_fopen(const char* filename, const char* mode)
{
    FILE* res = fopen(filename, mode);
    assert(res != NULL);
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get()); // TODO
    void* comp_addr = manager_register_mem_alloc(comp, sizeof(FILE));
    memcpy(comp_addr, res, sizeof(FILE));
    return comp_addr;
}

size_t
manager_fread(void* __restrict buf, size_t size, size_t count, FILE* __restrict fp)
{
    return fread(buf, size, count, fp);
}

size_t
manager_fwrite(void* __restrict buf, size_t size, size_t count, FILE* __restrict fp)
{
    return fwrite(buf, size, count, fp);
}

int
manager_fclose(FILE* fp)
{
    int res = fclose(fp);
    assert(res == 0);
    return res;
}

int
manager_getc(FILE* stream)
{
    return getc(stream);
}

int
manager___srget(FILE* stream)
{
    return __srget(stream);
}

void*
my_realloc(void* ptr, size_t to_alloc)
{
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get());

    if (ptr == NULL)
    {
        return my_malloc(to_alloc); // TODO
    }

    void* new_ptr = manager_register_mem_alloc(comp, to_alloc);
    struct mem_alloc* old_alloc = get_alloc_struct_from_ptr(comp, (uintptr_t) ptr);
    memcpy(new_ptr, ptr, to_alloc < old_alloc->size ? to_alloc : old_alloc->size);
    manager_free_mem_alloc(comp, ptr);
    return new_ptr;
}

void*
my_malloc(size_t to_alloc)
{
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get());
    assert(comp->scratch_mem_alloc + to_alloc < comp->scratch_mem_size);
    void* new_mem = manager_register_mem_alloc(comp, to_alloc);
    return new_mem;
}

void
my_free(void* ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get());
    manager_free_mem_alloc(comp, ptr); // TODO
    return;
}

int
my_fprintf(FILE* stream, const char* format, ...)
{
    va_list va_args;
    va_start(va_args, format);
    int res = vfprintf(stream, format, va_args);
    va_end(va_args);
    return res;
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
 *
 * For each function to be intercepted, we define the following:
 * redirect_func function to be executed at a higher privilege level
 * TODO I think the below three are common and can be lifted
 * intercept_ddc ddc to be installed for the transition
 * intercept_pcc
 *      higher privileged pcc pointing to the transition support function
 * sealed_redirect_cap
 *      sealed capability pointing to the consecutive intercept capabilities;
 *      this is the only component visible to the compartments
 */
void
setup_intercepts()
{
    for (size_t i = 0; i < sizeof(to_intercept_funcs) / sizeof(to_intercept_funcs[0]); ++i)
    {
        comp_intercept_funcs[i].func_name = to_intercept_funcs[i].func_name;
        comp_intercept_funcs[i].redirect_func = to_intercept_funcs[i].redirect_func;
        comp_intercept_funcs[i].intercept_ddc = manager_ddc;
        comp_intercept_funcs[i].intercept_pcc =
            cheri_address_set(cheri_pcc_get(), (uintptr_t) intercept_wrapper);
        void* __capability sealed_redirect_cap =
            cheri_address_set(manager_ddc, (uintptr_t) &comp_intercept_funcs[i].intercept_ddc);
        asm("SEAL %w[cap], %w[cap], lpb\n\t"
                : [cap]"+r"(sealed_redirect_cap)
                : /**/ );
        comp_intercept_funcs[i].redirect_cap = sealed_redirect_cap;
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
