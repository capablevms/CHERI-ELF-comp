#include "manager.h"

extern struct Compartment* loaded_comp;

struct CompEntryPoints
{
    char* file_name;
    char** entry_points;
    char** args;
};

// TODO
#define comp_entries_count 1
struct CompEntryPoints comp_entries[comp_entries_count] =
{
    "lua_script", (char*[]) { "do_script" }, NULL,
};

struct CompEntryPoints default_comp = { "default", (char*[]) {"main"}, NULL };

struct CompEntryPoints*
get_entry_points(char* comp_name)
{
    for (size_t i = 0; i < comp_entries_count; ++i)
    {
        if (!strcmp(comp_entries[i].file_name, comp_name))
        {
            return &comp_entries[i];
        }
    }
    return &default_comp;
}

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
    struct CompEntryPoints* file_entry_points = get_entry_points(file);
    struct Compartment* hw_comp = comp_from_elf(file, file_entry_points->entry_points);
    loaded_comp = hw_comp; // TODO
    log_new_comp(hw_comp);
    comp_map(hw_comp);
    int comp_result;
    size_t comp_args_count = 0;
    if (file_entry_points->args)
    {
        comp_args_count = sizeof(file_entry_points->args) / sizeof(file_entry_points->args[0]);
    }
    comp_result = comp_exec(hw_comp, file_entry_points->entry_points[0], (void**) file_entry_points->args, comp_args_count);
    comp_clean(hw_comp);
    return comp_result;
}
