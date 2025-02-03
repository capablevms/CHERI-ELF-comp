#include <limits.h>

#include "manager.h"

/* Test wrapper for compartments with arguments.
 *
 * Takes at least two arguments: one argument for the compartment binary name,
 * and one argument minimum to be passed to the compartment itself.
 * TODO currently hard coding the entry points and which entry point to call,
 * but plan to move this to some configuration file in the near future
 */

int
main(int argc, char **argv)
{
    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    assert(argc >= 3
        && "Expect at least two arguments: binary file for compartment, and "
           "entry function for compartment.");
    char *file = argv[1];

    struct Compartment *arg_comp = register_new_comp(file, false);
    struct CompMapping *arg_map = mapping_new(arg_comp);

    char *entry_func = argv[2];
    char **entry_func_args = NULL;
    if (argc > 3)
    {
        entry_func_args = &argv[3];
    }
    int comp_result = mapping_exec(arg_map, argv[2], entry_func_args);
    mapping_free(arg_map);
    comp_clean(arg_comp);
    return comp_result;
}
