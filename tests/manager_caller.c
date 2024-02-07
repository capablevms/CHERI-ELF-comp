#include "manager.h"

int
main(int argc, char **argv)
{
    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    assert(argc >= 2
        && "Expect at least one argument: binary file for compartment");
    char *file = argv[1];
    const char *prefix = "./";
    if (!strncmp(file, prefix, strlen(prefix)))
    {
        file += strlen(prefix);
    }

    struct Compartment *hw_comp = register_new_comp(file, true);
    comp_map(hw_comp);
    int comp_result = exec_comp(hw_comp, "main", NULL);
    comp_clean(hw_comp);
    return comp_result;
}
