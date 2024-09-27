#include "symbols_comp.h"

/*******************************************************************************
 * Forward static declarations
 ******************************************************************************/

static void
comp_syms_clean_one_entry(void *);
static int
comp_syms_compare(const void *, const void *);
static void
comp_syms_print_one(void *);

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

static void
comp_syms_clean_one_entry(void *sym)
{
    free(sym);
}

static int
comp_syms_compare(const void *arg, const void *item)
{
    return strcmp(
        (const char *) arg, ((const comp_symbol *) item)->sym_ref->sym_name);
}

static void
comp_syms_print_one(void *sym)
{
    comp_symbol *comp_sym = (comp_symbol *) sym;
    printf("COMP SYM ADDR %p - NAME %s - LIBSYM ADDR %p\n", sym,
        comp_sym->sym_ref->sym_name, (void *) comp_sym->sym_ref);
}

/*******************************************************************************
 * Main functions
 ******************************************************************************/

comp_symbol_list *
comp_syms_init()
{
    comp_symbol_list *new_list = malloc(sizeof(comp_symbol_list));
    tommy_hashtable_init(new_list, HASHTABLE_MAX_SZ);
    return new_list;
}

void
comp_syms_clean(comp_symbol_list *list)
{
    tommy_hashtable_done(list);
    free(list);
}

void
comp_syms_clean_deep(comp_symbol_list *list)
{
    tommy_hashtable_foreach(list, comp_syms_clean_one_entry);
    comp_syms_clean(list);
}

void
comp_syms_insert(comp_symbol *to_insert, comp_symbol_list *list)
{
    tommy_hashtable_insert(list, &to_insert->node, to_insert,
        hashtable_hash(to_insert->sym_ref->sym_name));
}

comp_symbol *
comp_syms_search(const char *to_find, comp_symbol_list *list)
{
    comp_symbol *found = tommy_hashtable_search(
        list, comp_syms_compare, to_find, hashtable_hash(to_find));
    return found;
}

comp_symbol **
comp_syms_find_all(const char *to_find, comp_symbol_list *list)
{
    comp_symbol **res = calloc(MAX_FIND_ALL_COUNT, sizeof(comp_symbol *));
    if (!res)
    {
        err(1,
            "Error allocating temporary memory for compartment symbol lookup!");
    }
    unsigned int res_sz = 0;
    tommy_hashtable_node *curr_node
        = tommy_hashtable_bucket(list, hashtable_hash(to_find));
    while (curr_node)
    {
        if (!strcmp(
                ((comp_symbol *) curr_node->data)->sym_ref->sym_name, to_find))
        {
            res[res_sz] = (comp_symbol *) curr_node->data;
            res_sz += 1;
        }
        curr_node = curr_node->next;
    }
    assert(res_sz < MAX_FIND_ALL_COUNT - 1);
    res = realloc(res, (res_sz + 1) * sizeof(comp_symbol *));
    return res;
}

void
comp_syms_print(comp_symbol_list *list)
{
    tommy_hashtable_foreach(list, comp_syms_print_one);
}

/*******************************************************************************
 * Specialised functions
 ******************************************************************************/

static void
gather_defined_sym(void *arg, void *sym)
{
    lib_symbol *lib_sym = (lib_symbol *) sym;
    if (lib_sym->sym_shndx != 0)
    {
        tommy_array_insert((tommy_array *) arg, lib_sym);
    }
}

void
update_comp_syms(comp_symbol_list *comp_syms, lib_symbol_list *lib_syms,
    const size_t lib_idx)
{
    tommy_array to_update;
    tommy_array_init(&to_update);
    tommy_hashtable_foreach_arg(lib_syms, gather_defined_sym, &to_update);
    lib_symbol *curr_sym;
    comp_symbol *new_cs;
    for (size_t i = 0; i < tommy_array_size(&to_update); ++i)
    {
        curr_sym = (lib_symbol *) tommy_array_get(&to_update, i);
        new_cs = malloc(sizeof(comp_symbol));
        new_cs->sym_ref = curr_sym;
        new_cs->sym_lib_idx = lib_idx;
        comp_syms_insert(new_cs, comp_syms);
    }
    tommy_array_done(&to_update);
}
