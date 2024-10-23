#include "compartment.c"
#include "manager.h"

int
main()
{
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    char *file = "./simple.so";
    struct Compartment *hw_comp = register_new_comp(file, true);
    for (size_t i = 0; i < 100; ++i)
    {
        comp_map(hw_comp);
        comp_unmap(hw_comp);
    }
    comp_clean(hw_comp);
    return 0;
}
