#include "manager.h"

extern struct Compartment* loaded_comp;

int
main(int argc, char** argv)
{
    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    char* comp_file_1 = "test_two_comps-comp1";
    char* comp_file_2 = "test_two_comps-comp2";

    // Set default entry point with no arguments to pass
    // Used for both compartments
    struct ConfigEntryPoint* main_cep = malloc(sizeof(struct ConfigEntryPoint));
    main_cep = set_default_entry_point(main_cep);

    // Load comp1
    struct Compartment* comp1 = comp_from_elf(comp_file_1, main_cep, 1);
    log_new_comp(comp1);
    comp_map(comp1);
    fprintf(stdout, "Mapped Comp 1\n");

    // Load comp2
    struct Compartment* comp2 = comp_from_elf(comp_file_2, main_cep, 1);
    log_new_comp(comp2);
    comp_map(comp2);
    fprintf(stdout, "Mapped Comp 2\n");

    int comp_result;

    // Run Comp 1
    loaded_comp = comp1;
    comp_result = comp_exec(comp1, "main", NULL, 0);
    comp_clean(comp1);

    // Run Comp 2
    loaded_comp = comp2;
    comp_result |= comp_exec(comp2, "main", NULL, 0);
    comp_clean(comp2);

    free(main_cep);
    return comp_result;
}
