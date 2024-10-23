#define ELF_ST_TYPE ELF64_ST_TYPE
#define R_AARCH64_TLS_TPREL64 R_AARCH64_TLS_TPREL

#define __capability

#include <stdint.h>

#define CHERI_COMP_LINUX

#include "../src/compartment.c"

extern char **environ;
char **proc_env_ptr;
void *__capability sealed_redirect_cap = NULL;

// XXX Should be unused
const unsigned short avg_sz_per_env_entry = 128;
const unsigned short max_env_count = 128;
const size_t max_env_sz
    = max_env_count * sizeof(char *) + avg_sz_per_env_entry * max_env_count;

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

    return (int64_t) fn;
}

int
main(int argc, char **argv)
{
    if (argc < 2)
    {
        errx(1, "Expected at least one argument: binary file for compartment!");
    }
    char *file = argv[1];

    proc_env_ptr = environ;

    struct CompEntryPointDef *mock_cep
        = malloc(sizeof(struct CompEntryPointDef));
    mock_cep->name = malloc(strlen("main") + 1);
    strcpy((char *) mock_cep->name, "main");
    mock_cep->arg_count = 0;
    mock_cep->args_type = NULL;

    struct CompConfig *mock_cc = malloc(sizeof(struct CompConfig));
    mock_cc->heap_size = 0x800000UL;
    mock_cc->stack_size = 0x80000UL;
    mock_cc->entry_points = mock_cep;
    mock_cc->entry_point_count = 1;
    mock_cc->base_address = (void *) 0x1000000UL;

    struct Compartment *hw_comp = comp_from_elf(file, mock_cc);
    hw_comp->id = 0;

    comp_map(hw_comp);
    comp_clean(hw_comp);
    return 0;
}
