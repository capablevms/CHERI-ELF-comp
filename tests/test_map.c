#include "manager.h"

int
main(int argc, char** argv)
{
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    char* file = "./simple";
    struct Compartment* hw_comp = comp_from_elf(file, NULL);
    log_new_comp(hw_comp);
    comp_map(hw_comp);
    comp_clean(hw_comp);
    return 0;
}
