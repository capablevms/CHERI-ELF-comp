#include "manager.h"

extern struct Compartment* loaded_comp;

int
main(int argc, char** argv)
{
    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    assert(argc == 2);
    char* file = argv[1];
    struct Compartment* hw_comp = comp_from_elf(file);
    loaded_comp = hw_comp; // TODO
    hw_comp->argc = 1;
    char* comp_argv[] = { file };
    hw_comp->argv = comp_argv;
    log_new_comp(hw_comp);
    comp_map(hw_comp);
    int comp_result = comp_exec(hw_comp);
    comp_clean(hw_comp);
    return comp_result;
}
