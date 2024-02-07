#include <limits.h>

#include "manager.h"

/* Test wrapper for compartments with arguments.
 *
 * Takes at least two arguments: one argument for the compartment binary name,
 * and one argument minimum to be passed to the compartment itself.
 * TODO currently hard coding the entry points and which entry point to call,
 * but plan to move this to some configuration file in the near future
 */

extern struct Compartment *loaded_comp;

int
main(int argc, char **argv)
{
    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    char *file = "test_ddc_overwrite";
    size_t entry_point_count = 0;
    struct ConfigEntryPoint *cep
        = parse_compartment_config(file, &entry_point_count);
    assert(cep);

    struct Compartment *arg_comp = comp_from_elf(file, cep, entry_point_count);
    log_new_comp(arg_comp);
    comp_map(arg_comp);

    int *secret = malloc(sizeof(int));
    *secret = 42;

    char *entry_func = "test_leak";
    size_t secret_addr_str_len
        = snprintf(NULL, 0, "%llu", (unsigned long long) secret);
    char *secret_addr_str = malloc(secret_addr_str_len + 1);
    sprintf(secret_addr_str, "%llu", (unsigned long long) secret);
    char *entry_func_args[1] = { secret_addr_str };
    struct ConfigEntryPoint comp_entry
        = get_entry_point(entry_func, cep, entry_point_count);
    void *comp_args = prepare_compartment_args(entry_func_args, comp_entry);

    int comp_result
        = comp_exec(arg_comp, entry_func, comp_args, comp_entry.arg_count);
    clean_compartment_config(cep, entry_point_count);
    comp_clean(arg_comp);
    assert(comp_result == *secret);
    free(secret_addr_str);
    return 0;
}
