#include "compartment.c"
#include "manager.h"

#include <stdio.h>

int
main()
{
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    char *file = "./simple.so";
    struct Compartment *hw_comp = register_new_comp(file, true);
    printf("REG DONE\n");
    struct CompMapping *hw_map = mapping_new(hw_comp);
    printf("\tsz - %#zx\n", hw_comp->total_size);
    printf("NEW DONE\n");
    mapping_free(hw_map);
    printf("FREE DONE\n");
    comp_clean(hw_comp);
    printf("CLEAN DONE\n");
    return 0;
}
