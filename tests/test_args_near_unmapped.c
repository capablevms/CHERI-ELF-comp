#include <limits.h>

#include "manager.h"

/* Test wrapper for compartments with arguments.
 *
 * Takes at least two arguments: one argument for the compartment binary name,
 * and one argument minimum to be passed to the compartment itself.
 * TODO currently hard coding the entry points and which entry point to call,
 * but plan to move this to some configuration file in the near future
 */

extern struct Compartment* loaded_comp;

int
main(int argc, char** argv)
{
    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    char* file = "args_simple";
    size_t entry_point_count = 0;
    struct ConfigEntryPoint* cep = parse_compartment_config(file, &entry_point_count);
    if (!cep)
    {
        cep = malloc(sizeof(struct ConfigEntryPoint));
        cep = set_default_entry_point(cep);
    }

    struct Compartment* arg_comp = comp_from_elf(file, cep, entry_point_count);
    loaded_comp = arg_comp; // TODO
    log_new_comp(arg_comp);
    comp_map(arg_comp);

    char* entry_func = "check_simple";
    char* entry_func_args[2] = { "40", "2" };
    struct ConfigEntryPoint comp_entry = get_entry_point(entry_func, cep, entry_point_count);
    void* comp_args = prepare_compartment_args(entry_func_args, comp_entry);

    // Allocate two pages worth of memory (ensure larger than size of args)...
    size_t page_size = sysconf(_SC_PAGESIZE);
    assert(page_size > comp_entry.arg_count * COMP_ARG_SIZE);
    size_t two_page_size = 2 * page_size;
    void* two_page_alloc = mmap(NULL, two_page_size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS, -1, 0);
    // ... move args in the first page, near page boundary ...
    void* memcpy_address = (char*) two_page_alloc + page_size - comp_entry.arg_count * COMP_ARG_SIZE;
    memcpy(memcpy_address, comp_args, comp_entry.arg_count * COMP_ARG_SIZE);
    // ... and set second page as inaccessible
    // ... and deallocate the second page
    munmap(two_page_alloc + page_size, page_size);
    free(comp_args);
    comp_args = memcpy_address;

    int comp_result = comp_exec(arg_comp, entry_func, comp_args, comp_entry.arg_count);
    clean_compartment_config(cep, entry_point_count);
    comp_clean(arg_comp);
    munmap(two_page_alloc, page_size);
    return comp_result;
}
