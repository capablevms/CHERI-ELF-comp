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

    // Read entry point data for compartment 1
    size_t ep_count = 0;
    struct ConfigEntryPoint* comp1_cep = parse_compartment_config(comp_file_1, &ep_count);
    struct ConfigEntryPoint* main_cep = malloc(sizeof(struct ConfigEntryPoint));
    main_cep = set_default_entry_point(main_cep);

    // Load comp1
    struct Compartment* comp1 = comp_from_elf(comp_file_1, comp1_cep, 1);
    log_new_comp(comp1);
    comp_map(comp1);
    fprintf(stdout, "Mapped Comp 1\n");

    // Load comp2
    struct Compartment* comp2 = comp_from_elf(comp_file_2, main_cep, 1);
    log_new_comp(comp2);
    comp_map(comp2);
    fprintf(stdout, "Mapped Comp 2\n");


    // Run Comp 1
    loaded_comp = comp1;
    int comp_result = comp_exec(comp1, "inter_call", NULL, 0);
    assert(comp_result == 0);
    comp_clean(comp1);
    comp_clean(comp2);

    free(comp1_cep);
    return comp_result;
}
