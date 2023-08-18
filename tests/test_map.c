#include "manager.h"

int
main(int argc, char** argv)
{
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    char* file = "./simple";

    // Set default entry point with no arguments to pass
    struct ConfigEntryPoint* main_cep = malloc(sizeof(struct ConfigEntryPoint));
    main_cep = set_default_entry_point(main_cep);

    struct Compartment* hw_comp = comp_from_elf(file, main_cep, 1);
    log_new_comp(hw_comp);
    comp_map(hw_comp);
    comp_clean(hw_comp);
    free(main_cep);
    return 0;
}
