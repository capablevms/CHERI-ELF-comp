#include "manager.h"

extern struct Compartment* loaded_comp;

int
main(int argc, char** argv)
{
    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    assert(argc >= 2 && "Expect at least one argument: binary file for compartment");
    char* file = argv[1];
    const char* prefix = "./";
    if (!strncmp(file, prefix, strlen(prefix)))
    {
        file += strlen(prefix);
    }

    // Set default entry point with no arguments to pass
    struct ConfigEntryPoint* main_cep = malloc(sizeof(struct ConfigEntryPoint));
    main_cep = set_default_entry_point(main_cep);

    struct Compartment* hw_comp = comp_from_elf(file, main_cep, 1);
    loaded_comp = hw_comp; // TODO
    log_new_comp(hw_comp);
    comp_map(hw_comp);
    int comp_result;
    size_t comp_args_count = 0;
    comp_result = comp_exec(hw_comp, "main", NULL, 0, NULL);
    comp_clean(hw_comp);
    free(main_cep);
    return comp_result;
}
