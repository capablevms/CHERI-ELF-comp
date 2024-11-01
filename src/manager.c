#include "manager.h"

// TODO consider moving to a struct or some global thing
static size_t comps_count = 0;
struct Compartment **comps;
struct Compartment *loaded_comp = NULL;

// Variables and functions related to laying compartments in memory
// TODO make start address configurable
static const uintptr_t comp_start_addr = 0x1000000UL;
static const unsigned short comp_page_interval_count = 2;
void *min_next_comp_addr = NULL;

// Name of config file entry for compartment parameters
static const char *config_file_param_entry = "compconfig";

void *__capability manager_ddc = 0;

const char *comp_config_suffix = ".comp";

char **proc_env_ptr = NULL;
size_t proc_env_ptr_sz = 0;
unsigned short proc_env_count = 0;
const unsigned short avg_sz_per_env_entry = 128; // TODO
const unsigned short max_env_count = 128; // TODO
const size_t max_env_sz
    = max_env_count * sizeof(char *) + avg_sz_per_env_entry * max_env_count;
extern char **environ;

// Functions

static struct CompConfig *
parse_compartment_config_file(char *, bool);
static void
parse_compartment_config_params(const toml_table_t *, struct CompConfig *);
static void
parse_compartment_config(struct CompConfig *);
static struct CompEntryPointDef *
make_default_comp_entry_point();
static struct CompConfig *
make_default_comp_config();
static struct CompEntryPointDef
get_entry_point(char *, const struct CompConfig *);
static void
prepare_compartment_environ();
static void *
prepare_compartment_args(char **args, struct CompEntryPointDef);

static struct Compartment *
get_comp(struct Compartment *);

// Printing
static void print_full_cap(uintcap_t);
static void
pp_cap(void *__capability);
static void
print_comp(struct Compartment *);

/*******************************************************************************
 * Utility functions
 ******************************************************************************/

static void
print_full_cap(uintcap_t cap)
{
    uint32_t words[4]; // Hack to demonstrate! In real code, be more careful
                       // about sizes, etc.
    printf("0x%d", cheri_tag_get(cap) ? 1 : 0);
    memcpy(words, &cap, sizeof(cap));
    for (int i = 3; i >= 0; i--)
    {
        printf("_%08x", words[i]);
    }
    printf("\n");
}

static void
pp_cap(void *__capability ptr)
{
    uint64_t length = cheri_length_get(ptr);
    uint64_t address = cheri_address_get(ptr);
    uint64_t base = cheri_base_get(ptr);
    uint64_t flags = cheri_flags_get(ptr);
    uint64_t perms = cheri_perms_get(ptr);
    uint64_t type = cheri_type_get(ptr);
    bool tag = cheri_tag_get(ptr);

    uint64_t offset = cheri_offset_get(ptr);

    printf("Capability: %#lp\n", ptr);
    printf("Tag: %d, Perms: %04lx, Type: %lx, Address: %04lx, Base: %04lx, "
           "End: %04lx, Flags: %lx, "
           "Length: %04lx, Offset: %04lx\n",
        tag, perms, type, address, base, base + length, flags, length, offset);
}

void *
get_next_comp_addr(void)
{
    if (min_next_comp_addr == NULL)
    {
        min_next_comp_addr = (void *) comp_start_addr;
    }
    return min_next_comp_addr;
}

struct Compartment *
register_new_comp(char *filename, bool allow_default_entry)
{
    if (!proc_env_ptr)
    {
        prepare_compartment_environ();
    }

    struct CompConfig *new_cc
        = parse_compartment_config_file(filename, allow_default_entry);
    new_cc->base_address = get_next_comp_addr();
    new_cc->env_ptr = proc_env_ptr;
    new_cc->env_ptr_sz = proc_env_ptr_sz;
    new_cc->env_ptr_count = proc_env_count;

    struct Compartment *new_comp = comp_from_elf(filename, new_cc);
    new_comp->id = comps_count;
    void *__capability new_comp_ddc
        = cheri_address_set(cheri_ddc_get(), (intptr_t) new_comp->base);
    new_comp_ddc = cheri_bounds_set(
        new_comp_ddc, (char *) new_comp->mem_top - (char *) new_comp->base);
    new_comp_ddc = cheri_offset_set(new_comp_ddc,
        (char *) new_comp->scratch_mem_stack_top - (char *) new_comp->base);
    new_comp->ddc = new_comp_ddc;

    comps_count += 1;
    comps = realloc(comps, comps_count * sizeof(struct Compartment *));
    comps[comps_count - 1] = new_comp;

    min_next_comp_addr = align_up((char *) comp_start_addr + new_comp->size
            + comp_page_interval_count * sysconf(_SC_PAGESIZE),
        sysconf(_SC_PAGESIZE));

    return new_comp;
}

int64_t
exec_comp(struct Compartment *to_exec, char *entry_fn, char **entry_fn_args)
{
    struct CompEntryPointDef comp_entry
        = get_entry_point(entry_fn, to_exec->cc);
    void *comp_args = prepare_compartment_args(entry_fn_args, comp_entry);

    struct Compartment *old_comp = loaded_comp;
    loaded_comp = to_exec;
    int64_t exec_res
        = comp_exec(to_exec, entry_fn, comp_args, comp_entry.arg_count);
    loaded_comp = old_comp;

    return exec_res;
}

void
clean_all_comps()
{
    for (size_t i = 0; i < comps_count; ++i)
    {
        clean_comp(comps[i]);
    }
    free(comps);

    free(proc_env_ptr);
    proc_env_ptr = NULL;
}

void
clean_comp(struct Compartment *to_clean)
{
    comp_clean(to_clean);
    // TODO move around memory from `comps`
}

static struct Compartment *
get_comp(struct Compartment *to_find)
{
    for (size_t i = 0; i < comps_count; ++i)
    {
        if (comps[i]->id == to_find->id)
        {
            return comps[i];
        }
    }
    errx(1, "Couldn't find requested compartment with id %zu.", to_find->id);
}

struct Compartment *
manager_find_compartment_by_addr(void *addr)
{
    size_t i;
    for (i = 0; i < comps_count; ++i)
    {
        if (comps[i]->base <= addr
            && (void *) ((char *) comps[i]->base + comps[i]->size) > addr)
        {
            break;
        }
    }
    assert(i != comps_count);
    return comps[i];
}

struct Compartment *
manager_find_compartment_by_ddc(void *__capability ddc)
{
    size_t i;
    for (i = 0; i < comps_count; ++i)
    {
        if (comps[i]->ddc == ddc)
        {
            return comps[i];
        }
    }
    // TODO improve error message with ddc
    errx(1, "Could not find compartment.");
}

struct Compartment *
manager_get_compartment_by_id(size_t id)
{
    assert(id < comps_count);
    return comps[id];
}

void
toml_parse_error(char *error_msg, char *errbuf)
{
    errx(1, "%s: %s\n", error_msg, errbuf);
}

char *
prep_config_filename(char *filename)
{
    // TODO do these string manipulation things leak?
    const char *prefix = "./";
    if (!strncmp(filename, prefix, strlen(prefix)))
    {
        filename += strlen(prefix);
    }
    const char *suffix_to_add = ".comp";
    char *config_filename
        = malloc(strlen(filename) + strlen(suffix_to_add) + 1);
    strcpy(config_filename, filename);
    const char *suffix = ".so";
    char *suffix_start = strrchr(config_filename, '.');
    if (suffix_start && !strcmp(suffix_start, suffix))
    {
        *suffix_start = '\0';
    }
    strcat(config_filename, suffix_to_add);
    return config_filename;
}

static void
parse_compartment_config_params(
    const toml_table_t *params, struct CompConfig *cc)
{
    assert(params);

    toml_datum_t heap_sz_t = toml_int_in(params, "heap");
    assert(heap_sz_t.ok);
    cc->heap_size = heap_sz_t.u.i;

    toml_datum_t stack_sz_t = toml_int_in(params, "stack");
    assert(stack_sz_t.ok);
    cc->stack_size = stack_sz_t.u.i;
}

static struct CompConfig *
parse_compartment_config_file(char *comp_filename, bool allow_default)
{
    // Get config file name
    char *config_filename = prep_config_filename(comp_filename);
    FILE *config_fd = fopen(config_filename, "r");
    free(config_filename);
    if (!config_fd)
    {
        assert(allow_default);
        errno = 0;
        return make_default_comp_config();
    }

    struct CompConfig *new_cc = malloc(sizeof(struct CompConfig));
    bool explicit_comp_szs = false;

    // Parse config file
    char toml_errbuf[200];
    toml_table_t *tab
        = toml_parse_file(config_fd, toml_errbuf, sizeof(toml_errbuf));
    if (!tab)
    {
        toml_parse_error("TOML table parse error", toml_errbuf);
    }
    size_t entry_point_count = toml_table_ntab(tab);
    new_cc->entry_point_count = entry_point_count;
    toml_table_t *comp_params = toml_table_in(tab, config_file_param_entry);
    if (comp_params)
    {
        parse_compartment_config_params(comp_params, new_cc);
        new_cc->entry_point_count -= 1;
    }

    struct CompEntryPointDef *entry_points;
    if (new_cc->entry_point_count == 0)
    {
        entry_points = make_default_comp_entry_point();
        new_cc->entry_point_count = 1;
    }
    else
    {
        entry_points = calloc(
            new_cc->entry_point_count, sizeof(struct CompEntryPointDef));
        for (size_t i = 0; i < entry_point_count; ++i)
        {
            const char *fname = toml_key_in(tab, i);
            assert(fname);
            if (!strcmp(fname, config_file_param_entry))
            {
                break;
            }
            toml_table_t *curr_func = toml_table_in(tab, fname);
            assert(curr_func);
            toml_array_t *func_arg_types
                = toml_array_in(curr_func, "args_type");
            assert(func_arg_types);
            size_t func_arg_count = toml_array_nelem(func_arg_types);

            entry_points[i].name = malloc(strlen(fname) + 1);
            strcpy(entry_points[i].name, fname);
            entry_points[i].arg_count = func_arg_count;
            entry_points[i].args_type = malloc(func_arg_count * sizeof(char *));
            entry_points[i].comp_addr = NULL;
            for (size_t j = 0; j < func_arg_count; ++j)
            {
                toml_datum_t func_arg_type = toml_string_at(func_arg_types, j);
                entry_points[i].args_type[j]
                    = malloc(strlen(func_arg_type.u.s) + 1);
                strcpy(entry_points[i].args_type[j], func_arg_type.u.s);
            }
        }
    }
    new_cc->entry_points = entry_points;
    fclose(config_fd);
    return new_cc;
}

static struct CompEntryPointDef
get_entry_point(char *entry_point_fn, const struct CompConfig *cc)
{
    struct CompEntryPointDef curr_ep;
    for (size_t i = 0; i < cc->entry_point_count; ++i)
    {
        if (!strcmp(cc->entry_points[i].name, entry_point_fn))
        {
            return cc->entry_points[i];
        }
    }
    errx(1, "Did not find entry point for function %s!\n", entry_point_fn);
}

static void
prepare_compartment_environ()
{
    proc_env_ptr = malloc(max_env_sz);
    memset(proc_env_ptr, 0, max_env_sz);
    /*char **proc_env_vals = proc_env_ptr + max_env_count * sizeof(char *);*/

    const uintptr_t vals_offset = max_env_count * sizeof(char *);
    for (char **curr_env = environ; *curr_env; curr_env++)
    {
        // We only save offsets for the pointers, since they'll be relocated
        // relative to the compartment base address
        proc_env_ptr[proc_env_count] = (char *) (vals_offset + proc_env_ptr_sz);
        strcpy(
            (char *) proc_env_ptr + vals_offset + proc_env_ptr_sz, *curr_env);

        proc_env_count += 1;
        proc_env_ptr_sz += strlen(*curr_env) + 1;
    }
    proc_env_ptr_sz += vals_offset;
    proc_env_ptr = realloc(proc_env_ptr, proc_env_ptr_sz);
}

static void *
prepare_compartment_args(char **args, struct CompEntryPointDef cep)
{
    void *parsed_args = calloc(COMP_ARG_SIZE, cep.arg_count);
    size_t allocated_args = 0;
    size_t to_copy;
    union arg_holder tmp;
    for (size_t i = 0; i < cep.arg_count; ++i)
    {
        if (!strcmp(cep.args_type[i], "int"))
        {
            tmp.i = atoi(args[i]);
            to_copy = sizeof(int);
        }
        else if (!strcmp(cep.args_type[i], "long"))
        {
            tmp.l = atol(args[i]);
            to_copy = sizeof(long);
        }
        else if (!strcmp(cep.args_type[i], "char"))
        {
            tmp.c = *args[i];
            to_copy = sizeof(char);
        }
        else if (!strcmp(cep.args_type[i], "long long"))
        {
            tmp.ll = atoll(args[i]);
            to_copy = sizeof(long long);
        }
        else if (!strcmp(cep.args_type[i], "unsigned long long"))
        {
            tmp.ull = strtoull(args[i], NULL, 10);
            to_copy = sizeof(unsigned long long);
        }
        else
        {
            errx(1, "Unhandled compartment argument type %s!\n",
                cep.args_type[i]);
        }
        memcpy((char *) parsed_args + i * COMP_ARG_SIZE, &tmp, to_copy);
    }
    return parsed_args;
}

static struct CompEntryPointDef *
make_default_comp_entry_point()
{
    struct CompEntryPointDef *cep = malloc(sizeof(struct CompEntryPointDef));
    cep->name = malloc(strlen("main") + 1);
    strcpy((char *) cep->name, "main");
    cep->arg_count = 0;
    cep->args_type = NULL;
    return cep;
}

static struct CompConfig *
make_default_comp_config()
{
    struct CompConfig *cc = malloc(sizeof(struct CompConfig));
    cc->heap_size = DEFAULT_COMP_HEAP_SZ;
    cc->stack_size = DEFAULT_COMP_STACK_SZ;
    cc->entry_points = make_default_comp_entry_point();
    cc->entry_point_count = 1;
    cc->base_address = NULL;
    return cc;
}

static void
print_comp(struct Compartment *to_print)
{
    printf("== COMPARTMENT\n");
    printf("- id : %lu\n", to_print->id);
    {
        printf("- DDC : ");
        printf(" base - 0x%lx ", cheri_base_get(to_print->ddc));
        printf(" length - 0x%lx ", cheri_length_get(to_print->ddc));
        printf(" address - 0x%lx ", cheri_address_get(to_print->ddc));
        printf(" offset - 0x%lx ", cheri_offset_get(to_print->ddc));
        printf("\n");
    }
    printf("- size : 0x%zx\n", to_print->size);
    printf("- base : %p\n", to_print->base);
    printf("- mem_top : %p\n", to_print->mem_top);
    printf("- mapped : %s\n", to_print->mapped ? "true" : "false");

    printf("- environ_ptr : %p\n", (void *) to_print->environ_ptr);
    printf("- environ_sz : 0x%zx\n", to_print->environ_sz);

    printf("- scratch_mem_base : %p\n", to_print->scratch_mem_base);
    printf("- scratch_mem_size : %#zx", to_print->scratch_mem_size);
    printf(" [0x%zx heap + %#zx stack]\n", to_print->scratch_mem_heap_size,
        to_print->scratch_mem_stack_size);
    printf("- scratch_mem_extra : %#zx", to_print->scratch_mem_extra);
    printf(" [%#zx tls + %#zx environ]\n", to_print->total_tls_size,
        to_print->environ_sz);
    printf(
        "- scratch_mem_heap_size : 0x%zx\n", to_print->scratch_mem_heap_size);
    printf("- scratch_mem_stack_top : %p\n", to_print->scratch_mem_stack_top);
    printf(
        "- scratch_mem_stack_size : 0x%zx\n", to_print->scratch_mem_stack_size);

    printf("- libs_count : %lu\n", to_print->libs_count);
    printf("- tls_lookup_func : %p\n", to_print->tls_lookup_func);
    printf("- total_tls_size : %#zx\n", to_print->total_tls_size);
    printf("- libs_tls_sects :\n");
    printf("\t> region_count : %hu\n", to_print->libs_tls_sects->region_count);
    printf("\t> region_size : 0x%zx\n", to_print->libs_tls_sects->region_size);
    // TODO region_start
    printf("\t> region_start : %p\n", to_print->libs_tls_sects->region_start);
    printf("\t> libs_count : %hu\n", to_print->libs_tls_sects->libs_count);
    printf("\n");

    printf("- page_size : %lu\n", to_print->page_size);

    printf("== DONE\n");
}
