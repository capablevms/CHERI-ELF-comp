#define ELF_ST_TYPE ELF64_ST_TYPE
#define R_AARCH64_TLS_TPREL64 R_AARCH64_TLS_TPREL

#define __capability

#include <stdbool.h>
#include <stdint.h>

#define CHERI_COMP_LINUX
typedef uintptr_t uintcap_t;

uint64_t
cheri_length_get(void *ptr)
{
    return (uint64_t) ptr;
}

uint64_t
cheri_address_get(void *ptr)
{
    return (uint64_t) ptr;
}

uint64_t
cheri_base_get(void *ptr)
{
    return (uint64_t) ptr;
}

uint64_t
cheri_flags_get(void *ptr)
{
    return (uint64_t) ptr;
}

uint64_t
cheri_perms_get(void *ptr)
{
    return (uint64_t) ptr;
}

uint64_t
cheri_type_get(void *ptr)
{
    return (uint64_t) ptr;
}

bool
cheri_tag_get(void *ptr)
{
    return ptr == 0x0;
}

uint64_t
cheri_offset_get(void *ptr)
{
    return (uint64_t) ptr;
}

void *
cheri_ddc_get()
{
    return 0x0;
}

void *
cheri_address_set(void *ptr, intptr_t addr)
{
    void *_ptr = ptr;
    return (void *) addr;
}

void *
cheri_bounds_set(void *ptr, intptr_t addr)
{
    intptr_t _addr = addr;
    return ptr;
}

void *
cheri_offset_set(void *ptr, intptr_t addr)
{
    intptr_t _addr = addr;
    return ptr;
}

#include "../src/compartment.c"
#include "../src/manager.c"

extern char **environ;
char **proc_env_ptr;
void *__capability sealed_redirect_cap = NULL;

int64_t
comp_exec_in(void *comp_sp, void *__capability comp_ddc, void *fn, void *args,
    size_t args_count, void *__capability src, void *tls)
{
    // Prevent `-Wno-unused-parameter` errors
    void *_comp_sp = comp_sp;
    void *__capability _comp_ddc = comp_ddc;
    void *_args = args;
    size_t _args_count = args_count;
    void *__capability _src = src;
    void *_tls = tls;

    int64_t res = ((int64_t(*)()) fn)();
    return res;
}

int
main(int argc, char **argv)
{
    if (argc < 2)
    {
        errx(1, "Expected at least one argument: binary file for compartment!");
    }
    char *file = argv[1];

    struct Compartment *hw_comp = register_new_comp(file, true);
    hw_comp->id = 0;

    struct CompMapping *hw_map = mapping_new(hw_comp);
    mapping_exec(hw_map, "main", NULL);
    mapping_free(hw_map);
    comp_clean(hw_comp);
    return 0;
}
