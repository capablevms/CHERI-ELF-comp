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

    struct Compartment *hw_comp = register_new_comp(file, true);
    struct CompMapping *hw_map = mapping_new(hw_comp);
    int comp_result = mapping_exec(hw_map, "main", NULL);
    mapping_free(hw_map);
    comp_clean(hw_comp);
    return comp_result;
}
