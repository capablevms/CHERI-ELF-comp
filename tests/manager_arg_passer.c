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

    assert(argc >= 4
        && "Expect at least three arguments: binary file for compartment, "
           "entry function for compartment, and at least one argument to pass "
           "to compartment function.");
    char *file = argv[1];

    struct Compartment *arg_comp = register_new_comp(file, false);
    struct CompMapping *arg_map = mapping_new(arg_comp);

    char *entry_func = argv[2];
    char **entry_func_args = &argv[3];
    int comp_result = mapping_exec(arg_map, argv[2], &argv[3]);
    mapping_free(arg_map);
    comp_clean(arg_comp);
    return comp_result;
}
