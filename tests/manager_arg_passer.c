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

struct CompEntryPoints
{
    char* file_name;
    char** entry_points;
    size_t arg_count;
    void** args;
};

#define comp_entries_count 4
struct CompEntryPoints comp_entries[comp_entries_count] =
{
    { "lua_script"   , (char*[]) { "do_script"  }, 0, NULL, },
    { "args_simple"  , (char*[]) { "check_fn"   }, 2, (void*[]) { (void*) 40,  (void*) 2} },
    { "args_combined", (char*[]) { "check_fn"   }, 3, (void*[]) { (void*) 400, (void*) '2', (void*) 20} },
    { "args_long_max", (char*[]) { "check_long" }, 1, (void*[]) { (void*) LLONG_MAX } },
};

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
    assert(false);
}

char*
get_entry_point_fn(struct CompEntryPoints* cep)
{
    return cep->entry_points[0];
}

void**
get_entry_point_args(struct CompEntryPoints* cep)
{
    void** comp_args = malloc(cep->arg_count * sizeof(void*));
    for (size_t i = 0; i < cep->arg_count; ++i)
    {
        void* arg_ptr = malloc(sizeof(cep->args[i]));
        memcpy(arg_ptr, &cep->args[i], sizeof(cep->args[i]));
        comp_args[i] = arg_ptr;
    }
    return comp_args;
}

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

void
args_clean(void** comp_args, size_t arg_count)
{
    for (size_t i = 0; i < arg_count; ++i)
    {
        free(comp_args[i]);
    }
    free(comp_args);
}

int
main(int argc, char** argv)
{
    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    assert(argc >= 3 && "Expect at least two arguments: binary file for compartment, and at least one argument to pass to compartment.");
    char* file = prep_filename(argv[1]);

    struct CompEntryPoints* cep = get_entry_points(file);
    struct Compartment* arg_comp = comp_from_elf(file, cep->entry_points);
    loaded_comp = arg_comp; // TODO
    log_new_comp(arg_comp);
    comp_map(arg_comp);


    void** comp_args = get_entry_point_args(cep);
    int comp_result = comp_exec(arg_comp, get_entry_point_fn(cep), comp_args, cep->arg_count);
    comp_clean(arg_comp);
    args_clean(comp_args, cep->arg_count);
    return comp_result;
}
