#include "symbols_lib.h"

/*******************************************************************************
 * Forward static declarations
 ******************************************************************************/

static void
lib_syms_clean_one_entry(void *);
static int
lib_syms_compare(const void *, const void *);
static void
lib_syms_print_one(void *);

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

static void
lib_syms_clean_one_entry(void *sym)
{
    lib_symbol *lib_sym = (lib_symbol *) sym;
    free(lib_sym->sym_name);
    free(lib_sym);
}

static int
lib_syms_compare(const void *arg, const void *item)
{
    return strcmp((const char *) arg, ((const lib_symbol *) item)->sym_name);
}

static void
lib_syms_print_one(void *sym)
{
    lib_symbol *lib_sym = (lib_symbol *) sym;
    printf("LIB SYM ADDR %p - NAME %s - OFF %p\n", sym, lib_sym->sym_name,
        lib_sym->sym_offset);
}

/*******************************************************************************
 * Main functions
 ******************************************************************************/

lib_symbol_list *
lib_syms_init()
{
    lib_symbol_list *new_list = malloc(sizeof(lib_symbol_list));
    tommy_hashtable_init(new_list, HASHTABLE_MAX_SZ);
    return new_list;
}

void
lib_syms_clean(lib_symbol_list *list)
{
    tommy_hashtable_done(list);
    free(list);
}

void
lib_syms_clean_deep(lib_symbol_list *list)
{
    tommy_hashtable_foreach(list, lib_syms_clean_one_entry);
    lib_syms_clean(list);
}

void
lib_syms_insert(lib_symbol *to_insert, lib_symbol_list *list)
{
    tommy_hashtable_insert(
        list, &to_insert->node, to_insert, hashtable_hash(to_insert->sym_name));
}

lib_symbol *
lib_syms_search(const char *to_find, lib_symbol_list *list)
{
    lib_symbol *found = tommy_hashtable_search(
        list, lib_syms_compare, to_find, hashtable_hash(to_find));
    if (!found)
    {
        errx(1, "Did not find symbol %s!\n", to_find);
    }
    return found;
}

lib_symbol **
lib_syms_find_all(const char *to_find, lib_symbol_list *list)
{
    lib_symbol **res = calloc(MAX_FIND_ALL_COUNT, sizeof(lib_symbol *));
    if (!res)
    {
        err(1, "Error allocating temporary memory for library symbol lookup!");
    }
    unsigned int res_sz = 0;
    tommy_hashtable_node *curr_node
        = tommy_hashtable_bucket(list, hashtable_hash(to_find));
    while (curr_node)
    {
        if (!strcmp(((lib_symbol *) curr_node->data)->sym_name, to_find))
        {
            res[res_sz] = (lib_symbol *) curr_node->data;
            res_sz += 1;
        }
        curr_node = curr_node->next;
    }
    assert(res_sz < MAX_FIND_ALL_COUNT - 1);
    res = realloc(res, (res_sz + 1) * sizeof(lib_symbol *));
    return res;
}

void
lib_syms_print(lib_symbol_list *list)
{
    tommy_hashtable_foreach(list, lib_syms_print_one);
}
