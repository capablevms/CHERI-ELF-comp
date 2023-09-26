#include "manager.h"

const char* comp_env_fields[] = { "PATH", };
void* __capability comp_return_caps[COMP_RETURN_CAPS_COUNT];
void* __capability manager_ddc = 0;
struct Compartment* loaded_comp = NULL; // TODO
struct func_intercept comp_intercept_funcs[INTERCEPT_FUNC_COUNT];

const char* comp_config_suffix = ".comp";

const char*
get_env_str(const char* env_name)
{
    size_t env_name_len = strlen(env_name);
    for (char** env = environ; env != NULL; ++env) {
        const char* str = *env;
        if (strncmp(str, env_name, env_name_len) == 0 && str[env_name_len] == '=')
            return str;
    }
    return NULL;
}

/*******************************************************************************
 * Intercept functions
 *
 * These functions are meant to be executed within a manager context, by
 * intercepting certain functions within compartments which must have higher
 * privlige
 ******************************************************************************/

time_t
manager_time(time_t* t)
{
    return time(t);
}

/* As we are performing data compartmentalization, we must store relevant
 * information for accessing an opened file within compartment memory. However,
 * as we are using a bump allocator for internal memory management, we do not
 * have the capability of `free`ing this memory. A future implementation of a
 * better memory allocator will resolve this issue.
 */
FILE*
manager_fopen(const char* filename, const char* mode)
{
    FILE* res = fopen(filename, mode);
    assert(res != NULL);
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get()); // TODO
    void* comp_addr = manager_register_mem_alloc(comp, sizeof(FILE));
    memcpy(comp_addr, res, sizeof(FILE));
    return comp_addr;
}

size_t
manager_fread(void* __restrict buf, size_t size, size_t count, FILE* __restrict fp)
{
    return fread(buf, size, count, fp);
}

size_t
manager_fwrite(void* __restrict buf, size_t size, size_t count, FILE* __restrict fp)
{
    return fwrite(buf, size, count, fp);
}

int
manager_fputc(int chr, FILE* stream)
{
    return fputc(chr, stream);
}

int
manager_fclose(FILE* fp)
{
    int res = fclose(fp);
    assert(res == 0);
    return res;
}

int
manager_getc(FILE* stream)
{
    return getc(stream);
}

// Needed by test `lua_script`
int
manager___srget(FILE* stream)
{
    return __srget(stream);
}

void*
my_realloc(void* ptr, size_t to_alloc)
{
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get());

    if (ptr == NULL)
    {
        return my_malloc(to_alloc); // TODO
    }

    void* new_ptr = manager_register_mem_alloc(comp, to_alloc);
    struct mem_alloc* old_alloc = get_alloc_struct_from_ptr(comp, (uintptr_t) ptr);
    memcpy(new_ptr, ptr, to_alloc < old_alloc->size ? to_alloc : old_alloc->size);
    manager_free_mem_alloc(comp, ptr);
    return new_ptr;
}

void*
my_malloc(size_t to_alloc)
{
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get());
    assert(comp->scratch_mem_alloc + to_alloc < comp->scratch_mem_size);
    void* new_mem = manager_register_mem_alloc(comp, to_alloc);
    return new_mem;
}

void
my_free(void* ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    struct Compartment* comp = manager_find_compartment_by_ddc(cheri_ddc_get());
    manager_free_mem_alloc(comp, ptr); // TODO
    return;
}

int
my_fprintf(FILE* stream, const char* format, ...)
{
    va_list va_args;
    va_start(va_args, format);
    int res = vfprintf(stream, format, va_args);
    va_end(va_args);
    return res;
}

size_t
my_call_comp(size_t comp_id, char* fn_name, void* args, size_t args_count)
{
    struct Compartment* to_call = manager_get_compartment_by_id(comp_id);
    return comp_exec(to_call, fn_name, args, args_count);
}

/*******************************************************************************
 * Utility functions
 ******************************************************************************/

void print_full_cap(uintcap_t cap) {
    uint32_t words[4];  // Hack to demonstrate! In real code, be more careful about sizes, etc.
    printf("0x%d", cheri_tag_get(cap) ? 1 : 0);
    memcpy(words, &cap, sizeof(cap));
    for (int i = 3; i >= 0; i--) {
        printf("_%08x", words[i]);
    }
    printf("\n");
}

/* Setup required capabilities on the heap to jump from within compartments via
 * a context switch
 *
 * For each function to be intercepted, we define the following:
 * redirect_func function to be executed at a higher privilege level
 * TODO I think the below three are common and can be lifted
 * intercept_ddc ddc to be installed for the transition
 * intercept_pcc
 *      higher privileged pcc pointing to the transition support function
 * sealed_redirect_cap
 *      sealed capability pointing to the consecutive intercept capabilities;
 *      this is the only component visible to the compartments
 */
void
setup_intercepts()
{
    for (size_t i = 0; i < sizeof(to_intercept_funcs) / sizeof(to_intercept_funcs[0]); ++i)
    {
        comp_intercept_funcs[i].func_name = to_intercept_funcs[i].func_name;
        comp_intercept_funcs[i].redirect_func = to_intercept_funcs[i].redirect_func;
        comp_intercept_funcs[i].intercept_ddc = manager_ddc;
        comp_intercept_funcs[i].intercept_pcc =
            cheri_address_set(cheri_pcc_get(), (uintptr_t) intercept_wrapper);
        void* __capability sealed_redirect_cap =
            cheri_address_set(manager_ddc, (uintptr_t) &comp_intercept_funcs[i].intercept_ddc);
        asm("SEAL %[cap], %[cap], lpb\n\t"
                : [cap]"+C"(sealed_redirect_cap)
                : /**/ );
        comp_intercept_funcs[i].redirect_cap = sealed_redirect_cap;
    }
    comp_return_caps[0] = manager_ddc; // TODO does this need to be sealed?
    comp_return_caps[1] = cheri_address_set(cheri_pcc_get(), (uintptr_t) comp_exec_out);
}

struct Compartment*
manager_find_compartment_by_addr(void* ptr)
{
    return loaded_comp; // TODO
}

struct Compartment*
manager_find_compartment_by_ddc(void* __capability ddc)
{
    return loaded_comp; // TODO
}

struct Compartment*
manager_get_compartment_by_id(size_t id)
{
    return comps[id];
}

void
toml_parse_error(char* error_msg, char* errbuf)
{
    printf("%s: %s\n", error_msg, errbuf);
    exit(1);
}

char*
prep_config_filename(char* filename)
{
    const char* prefix = "./";
    if (!strncmp(filename, prefix, strlen(prefix)))
    {
        filename += strlen(prefix);
    }
    const char* suffix_to_add = ".comp";
    char* config_filename = malloc(strlen(filename) + strlen(suffix_to_add) + 1);
    strcpy(config_filename, filename);
    strcat(config_filename, suffix_to_add);
    return config_filename;
}

struct ConfigEntryPoint*
parse_compartment_config(char* comp_filename, size_t* entry_point_count)
{
    // Get config file name
    char* config_filename = prep_config_filename(comp_filename);
    FILE* config_fd = fopen(config_filename,"r");
    free(config_filename);
    if (!config_fd)
    {
        return NULL;
    }

    // Parse config file
    char toml_errbuf[200];
    toml_table_t* tab = toml_parse_file(config_fd, toml_errbuf, sizeof(toml_errbuf));
    if (!tab)
    {
        toml_parse_error("TOML table parse error", toml_errbuf);
    }
    *entry_point_count = toml_table_ntab(tab);
    struct ConfigEntryPoint* entry_points = malloc(*entry_point_count * sizeof(struct ConfigEntryPoint));
    for (size_t i = 0; i < *entry_point_count; ++i)
    {
        const char* fname = toml_key_in(tab, i);
        assert(fname);
        toml_table_t* curr_func = toml_table_in(tab, fname);
        assert(curr_func);
        toml_array_t* func_arg_types = toml_array_in(curr_func, "args_type");
        assert(func_arg_types);
        size_t func_arg_count = toml_array_nelem(func_arg_types);

        entry_points[i].name = fname;
        entry_points[i].arg_count = func_arg_count;
        entry_points[i].args_type = malloc(func_arg_count * sizeof(char*));
        for (size_t j = 0; j < func_arg_count; ++j)
        {
            toml_datum_t func_arg_type = toml_string_at(func_arg_types, j);
            entry_points[i].args_type[j] = malloc(strlen(func_arg_type.u.s) + 1);
            strcpy(entry_points[i].args_type[j], func_arg_type.u.s);
        }
    }
    fclose(config_fd);
    return entry_points;
}

void
clean_compartment_config(struct ConfigEntryPoint* cep, size_t entry_point_count)
{
    for (size_t i = 0; i < entry_point_count; ++i)
    {
        for (size_t j = 0; j < cep[i].arg_count; ++j)
        {
            free(cep[i].args_type[j]);
        }
        free(cep[i].args_type);
    }
    free(cep);
}

struct ConfigEntryPoint
get_entry_point(char* entry_point_fn, struct ConfigEntryPoint* ceps, size_t cep_count)
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
    printf("Did not find entry point for function %s!\n", entry_point_fn);
    assert(false);
}

void*
prepare_compartment_args(char** args, struct ConfigEntryPoint cep)
{
    void* parsed_args = calloc(COMP_ARG_SIZE, cep.arg_count);
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
            printf("Unhandled compartment argument type %s!\n", cep.args_type[i]);
            assert(false);
        }
        memcpy(parsed_args + i * COMP_ARG_SIZE, &tmp, to_copy);
    }
    return parsed_args;
}

struct ConfigEntryPoint*
set_default_entry_point(struct ConfigEntryPoint* cep)
{
    cep->name = malloc(strlen("main") + 1);
    strcpy((char*) cep->name, "main");
    cep->arg_count = 0;
    cep->args_type = NULL;
    return cep;
}
