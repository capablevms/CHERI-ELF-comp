#include "manager.h"

int
main(int argc, char **argv)
{
    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    char *comp_file_1 = "test_two_comps-comp1";
    char *comp_file_2 = "test_two_comps-comp2";

    // Load comp1
    struct Compartment *comp1 = register_new_comp(comp_file_1, true);
    comp_map(comp1);
    fprintf(stdout, "Mapped Comp 1\n");

    // Load comp2
    struct Compartment *comp2 = register_new_comp(comp_file_2, true);
    comp_map(comp2);
    fprintf(stdout, "Mapped Comp 2\n");

    int comp_result;

    // Run Comp 1
    comp_result = comp_exec(comp1, "main", NULL, 0);
    comp_clean(comp1);

    // Run Comp 2
    comp_result |= comp_exec(comp2, "main", NULL, 0);
    comp_clean(comp2);

    return comp_result;
}
