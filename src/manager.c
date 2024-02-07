#include "manager.h"

// TODO consider moving to a struct or some global thing
static size_t comps_count = 0;
struct CompWithEntries **comps;
struct Compartment *loaded_comp = NULL;

// Variables and functions related to laying compartments in memory
// TODO make start address configurable
const uintptr_t comp_start_addr = 0x1000000UL;
const unsigned short comp_page_interval_count = 2;
void *min_next_comp_addr = NULL;

const char *comp_env_fields[] = {
    "PATH",
};
void *__capability manager_ddc = 0;

const char *comp_config_suffix = ".comp";

static struct ConfigEntryPoint *
parse_compartment_config(char *, size_t *, bool);
static struct ConfigEntryPoint *
make_default_entry_point();
static struct ConfigEntryPoint
get_entry_point(char *, struct ConfigEntryPoint *, size_t);
static void *
prepare_compartment_args(char **args, struct ConfigEntryPoint);

static struct CompWithEntries *
get_comp_with_entries(struct Compartment *);

const char *
get_env_str(const char *env_name)
{
    size_t env_name_len = strlen(env_name);
    for (char **env = environ; env != NULL; ++env)
    {
        const char *str = *env;
        if (strncmp(str, env_name, env_name_len) == 0
            && str[env_name_len] == '=')
            return str;
    }
    return NULL;
}

/*******************************************************************************
 * Utility functions
 ******************************************************************************/

void
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
    size_t new_comp_ep_count;
    struct ConfigEntryPoint *new_cep = parse_compartment_config(
        filename, &new_comp_ep_count, allow_default_entry);

    char **ep_names = calloc(new_comp_ep_count, sizeof(char *));
    for (size_t i = 0; i < new_comp_ep_count; ++i)
    {
        ep_names[i] = malloc(strlen(new_cep[i].name) + 1);
        strcpy(ep_names[i], new_cep[i].name);
    }

    char **intercept_names = calloc(INTERCEPT_FUNC_COUNT, sizeof(char *));
    void **intercept_addrs = calloc(INTERCEPT_FUNC_COUNT, sizeof(uintptr_t));
    for (size_t i = 0; i < INTERCEPT_FUNC_COUNT; ++i)
    {
        intercept_names[i] = malloc(strlen(comp_intercept_funcs[i].func_name));
        strcpy(intercept_names[i], comp_intercept_funcs[i].func_name);
        intercept_addrs[i] = comp_intercept_funcs[i].redirect_func;
    }

    struct Compartment *new_comp
        = comp_from_elf(filename, ep_names, new_comp_ep_count, intercept_names,
            intercept_addrs, INTERCEPT_FUNC_COUNT, get_next_comp_addr());
    new_comp->id = comps_count;
    void *__capability new_comp_ddc
        = cheri_address_set(cheri_ddc_get(), (uintptr_t) new_comp->base);
    // TODO double check second parameter of `cheri_bounds_set`
    new_comp_ddc = cheri_bounds_set(
        new_comp_ddc, (uintptr_t) new_comp->scratch_mem_stack_top);
    new_comp->ddc = new_comp_ddc;

    struct CompWithEntries *new_cwe = malloc(sizeof(struct CompWithEntries));
    comps = realloc(comps, comps_count * sizeof(struct CompWithEntries *));
    comps[comps_count] = malloc(sizeof(struct CompWithEntries));
    comps[comps_count]->comp = new_comp;
    comps[comps_count]->cep = new_cep;
    comps_count += 1;

    min_next_comp_addr = align_up((char *) comp_start_addr + new_comp->size
            + comp_page_interval_count * sysconf(_SC_PAGESIZE),
        sysconf(_SC_PAGESIZE));

    for (size_t i = 0; i < new_comp_ep_count; ++i)
    {
        free(ep_names[i]);
    }
    free(ep_names);
    for (size_t i = 0; i < INTERCEPT_FUNC_COUNT; ++i)
    {
        free(intercept_names[i]);
    }
    free(intercept_names);
    free(intercept_addrs);

    return new_comp;
}

int64_t
exec_comp(struct Compartment *to_exec, char *entry_fn, char **entry_fn_args)
{
    struct CompWithEntries *comp_to_run = get_comp_with_entries(to_exec);
    struct ConfigEntryPoint comp_entry = get_entry_point(
        entry_fn, comp_to_run->cep, to_exec->entry_point_count);
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
        clean_comp(comps[i]->comp);
    }
    free(comps);
}

void
clean_comp(struct Compartment *to_clean)
{
    comp_clean(to_clean);
    struct CompWithEntries *cwe = get_comp_with_entries(to_clean);
    free(cwe->comp);
    free(cwe->cep);
    free(cwe);
    // TODO move around memory from `comps`
}

static struct CompWithEntries *
get_comp_with_entries(struct Compartment *to_find)
{
    for (size_t i = 0; i < comps_count; ++i)
    {
        if (comps[i]->comp->id == to_find->id)
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
        if (comps[i]->comp->base <= addr
            && (void *) ((char *) comps[i]->comp->base + comps[i]->comp->size)
                > addr)
        {
            break;
        }
    }
    assert(i != comps_count);
    return comps[i]->comp;
}

struct Compartment *
manager_find_compartment_by_ddc(void *__capability ddc)
{
    size_t i;
    for (i = 0; i < comps_count; ++i)
    {
        if (comps[i]->comp->ddc == ddc)
        {
            return comps[i]->comp;
        }
    }
    // TODO improve error message with ddc
    errx(1, "Could not find compartment.");
}

struct Compartment *
manager_get_compartment_by_id(size_t id)
{
    assert(id < comps_count);
    return comps[id]->comp;
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

static struct ConfigEntryPoint *
parse_compartment_config(
    char *comp_filename, size_t *entry_point_count, bool allow_default)
{
    // Get config file name
    char *config_filename = prep_config_filename(comp_filename);
    FILE *config_fd = fopen(config_filename, "r");
    free(config_filename);
    if (!config_fd)
    {
        assert(allow_default);
        errno = 0;
        *entry_point_count = 1;
        return make_default_entry_point();
    }

    // Parse config file
    char toml_errbuf[200];
    toml_table_t *tab
        = toml_parse_file(config_fd, toml_errbuf, sizeof(toml_errbuf));
    if (!tab)
    {
        toml_parse_error("TOML table parse error", toml_errbuf);
    }
    *entry_point_count = toml_table_ntab(tab);
    struct ConfigEntryPoint *entry_points
        = malloc(*entry_point_count * sizeof(struct ConfigEntryPoint));
    for (size_t i = 0; i < *entry_point_count; ++i)
    {
        const char *fname = toml_key_in(tab, i);
        assert(fname);
        toml_table_t *curr_func = toml_table_in(tab, fname);
        assert(curr_func);
        toml_array_t *func_arg_types = toml_array_in(curr_func, "args_type");
        assert(func_arg_types);
        size_t func_arg_count = toml_array_nelem(func_arg_types);

        entry_points[i].name = fname;
        entry_points[i].arg_count = func_arg_count;
        entry_points[i].args_type = malloc(func_arg_count * sizeof(char *));
        for (size_t j = 0; j < func_arg_count; ++j)
        {
            toml_datum_t func_arg_type = toml_string_at(func_arg_types, j);
            entry_points[i].args_type[j]
                = malloc(strlen(func_arg_type.u.s) + 1);
            strcpy(entry_points[i].args_type[j], func_arg_type.u.s);
        }
    }
    fclose(config_fd);
    return entry_points;
}

void
clean_compartment_config(struct ConfigEntryPoint *cep, size_t entry_point_count)
{
    for (size_t i = 0; i < entry_point_count; ++i)
    {
        free((void *) cep[i].name);
        for (size_t j = 0; j < cep[i].arg_count; ++j)
        {
            free(cep[i].args_type[j]);
        }
        free(cep[i].args_type);
    }
    free(cep);
}

static struct ConfigEntryPoint
get_entry_point(
    char *entry_point_fn, struct ConfigEntryPoint *ceps, size_t cep_count)
{
    struct ConfigEntryPoint curr_ep;
    while (cep_count != 0)
    {
        curr_ep = ceps[cep_count - 1];
        if (!strcmp(curr_ep.name, entry_point_fn))
        {
            return curr_ep;
        }
        cep_count -= 1;
    }
    errx(1, "Did not find entry point for function %s!\n", entry_point_fn);
}

static void *
prepare_compartment_args(char **args, struct ConfigEntryPoint cep)
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

static struct ConfigEntryPoint *
make_default_entry_point()
{
    struct ConfigEntryPoint *cep = malloc(sizeof(struct ConfigEntryPoint));
    cep->name = malloc(strlen("main") + 1);
    strcpy((char *) cep->name, "main");
    cep->arg_count = 0;
    cep->args_type = NULL;
    return cep;
}
