#include <limits.h>

#include "manager.h"

/* Test wrapper for compartments with arguments.
 *
 * Takes at least two arguments: one argument for the compartment binary name,
 * and one argument minimum to be passed to the compartment itself.
 * TODO currently hard coding the entry points and which entry point to call,
 * but plan to move this to some configuration file in the near future
 */

extern struct Compartment* loaded_comp;

char*
prep_filename(char* filename)
{
    const char* prefix = "./";
    if (!strncmp(filename, prefix, strlen(prefix)))
    {
        filename += strlen(prefix);
    }
    return filename;
}

int
main(int argc, char** argv)
{
    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    assert(argc >= 4 && "Expect at least three arguments: binary file for compartment, entry function for compartment, and at least one argument to pass to compartment function.");
    char* file = prep_filename(argv[1]);
    char* file_config = malloc(sizeof(file) + sizeof(comp_config_suffix) + 1);
    strcpy(file_config, file);
    strcat(file_config, comp_config_suffix);
    FILE* comp_config_fd = fopen(file_config, "r");
    free(file_config);
    struct ConfigEntryPoint* cep = NULL;
    size_t entry_point_count = 0;
    char** entry_points = NULL;
    if (comp_config_fd)
    {
        cep = parse_compartment_config(comp_config_fd, &entry_point_count);
        fclose(comp_config_fd);
    }
    // TODO else set main as default entry point

    struct Compartment* arg_comp = comp_from_elf(file, cep, entry_point_count);
    loaded_comp = arg_comp; // TODO
    log_new_comp(arg_comp);
    comp_map(arg_comp);

    char* entry_func = argv[2];
    char** entry_func_args = &argv[3];
    struct ConfigEntryPoint comp_entry = get_entry_point(entry_func, cep, entry_point_count);
    void* comp_args = prepare_compartment_args(entry_func_args, comp_entry);
    int comp_result = comp_exec(arg_comp, entry_func, comp_args, comp_entry.arg_count, comp_entry.args_sizes);
    clean_compartment_config(cep, entry_point_count);
    comp_clean(arg_comp);
    return comp_result;
}
