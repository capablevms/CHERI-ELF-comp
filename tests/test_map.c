#include "manager.h"
#include "compartment.c"

int
main()
{
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    char* file = "./simple.so";
    struct Compartment* hw_comp = register_new_comp(file, true);
    comp_map(hw_comp);
    comp_clean(hw_comp);
    return 0;
}
