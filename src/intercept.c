#include "intercept.h"

struct FuncIntercept comp_intercept_funcs[INTERCEPT_FUNC_COUNT];
void *__capability comp_return_caps[COMP_RETURN_CAPS_COUNT];
void *__capability sealed_redirect_cap;

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
    for (size_t i = 0;
         i < sizeof(to_intercept_funcs) / sizeof(to_intercept_funcs[0]); ++i)
    {
        comp_intercept_funcs[i].func_name = to_intercept_funcs[i].func_name;
        comp_intercept_funcs[i].redirect_func
            = to_intercept_funcs[i].redirect_func;
        comp_intercept_funcs[i].intercept_pcc
            = cheri_address_set(cheri_pcc_get(), (uintptr_t) intercept_wrapper);
    }
    sealed_redirect_cap = manager_ddc;
    sealed_redirect_cap
        = cheri_address_set(sealed_redirect_cap, (intptr_t) comp_return_caps);
    asm("SEAL %[cap], %[cap], lpb\n\t"
        : [cap] "+C"(sealed_redirect_cap)
        : /**/);
    comp_return_caps[0] = manager_ddc; // TODO does this need to be sealed?
    comp_return_caps[1]
        = cheri_address_set(cheri_pcc_get(), (uintptr_t) comp_exec_out);
}

/*******************************************************************************
 * Intercept functions
 *
 * These functions are meant to be executed within a manager context, by
 * intercepting certain functions within compartments which must have higher
 * privlige
 ******************************************************************************/

time_t
intercepted_time(time_t *t)
{
    return time(t);
}

/* As we are performing data compartmentalization, we must store relevant
 * information for accessing an opened file within compartment memory. However,
 * as we are using a bump allocator for internal memory management, we do not
 * have the capability of `free`ing this memory. A future implementation of a
 * better memory allocator will resolve this issue.
 */
FILE *
intercepted_fopen(const char *filename, const char *mode)
{
    FILE *res = fopen(filename, mode);
    assert(res != NULL);
    /*struct Compartment* comp =
     * manager_find_compartment_by_ddc(cheri_ddc_get()); // TODO*/
    void *comp_addr = manager_register_mem_alloc(loaded_comp, sizeof(FILE));
    memcpy(comp_addr, res, sizeof(FILE));
    return comp_addr;
}

size_t
intercepted_fread(
    void *__restrict buf, size_t size, size_t count, FILE *__restrict fp)
{
    return fread(buf, size, count, fp);
}

size_t
intercepted_fwrite(
    void *__restrict buf, size_t size, size_t count, FILE *__restrict fp)
{
    return fwrite(buf, size, count, fp);
}

int
intercepted_fputc(int chr, FILE *stream)
{
    return fputc(chr, stream);
}

int
intercepted_fclose(FILE *fp)
{
    int res = fclose(fp);
    assert(res == 0);
    return res;
}

int
intercepted_getc(FILE *stream)
{
    return getc(stream);
}

// Needed by test `lua_script`
int
intercepted___srget(FILE *stream)
{
    return __srget(stream);
}

void *
my_realloc(void *ptr, size_t to_alloc)
{
    // TODO revisit this logic; do we keep a pointer in the manager of the
    // currently loaded compartment (would probably require this to be set in
    // the transition function), or do we get this information from the
    // intercept source (could check the compartment mapping to see which
    // compartment the source address comes from)
    /*struct Compartment* comp =
     * manager_find_compartment_by_ddc(cheri_ddc_get());*/
    struct Compartment *comp = loaded_comp;

    if (ptr == NULL)
    {
        return my_malloc(to_alloc); // TODO
    }

    void *new_ptr = manager_register_mem_alloc(comp, to_alloc);
    struct MemAlloc *old_alloc
        = get_alloc_struct_from_ptr(comp, (uintptr_t) ptr);
    memcpy(
        new_ptr, ptr, to_alloc < old_alloc->size ? to_alloc : old_alloc->size);
    manager_free_mem_alloc(comp, ptr);
    return new_ptr;
}

void *
my_malloc(size_t to_alloc)
{
    /*struct Compartment* comp =
     * manager_find_compartment_by_ddc(cheri_ddc_get());*/
    struct Compartment *comp = loaded_comp;
    assert(comp->scratch_mem_alloc + to_alloc < comp->scratch_mem_size);
    void *new_mem = manager_register_mem_alloc(comp, to_alloc);
    return new_mem;
}

void
my_free(void *ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    /*struct Compartment* comp =
     * manager_find_compartment_by_ddc(cheri_ddc_get());*/
    manager_free_mem_alloc(loaded_comp, ptr); // TODO
    return;
}

int
my_fprintf(FILE *stream, const char *format, ...)
{
    va_list va_args;
    va_start(va_args, format);
    int res = vfprintf(stream, format, va_args);
    va_end(va_args);
    return res;
}

size_t
my_call_comp(size_t comp_id, char *fn_name, void *args, size_t args_count)
{
    struct Compartment *to_call = manager_get_compartment_by_id(comp_id);
    return exec_comp(to_call, fn_name, args);
    /*return exec_comp(to_call, fn_name, args, args_count);*/
}
