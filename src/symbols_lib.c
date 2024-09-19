#include "symbols.h"

static void
lib_syms_clean_one_entry(lib_symbol *sym)
{
    free(sym->sym_name);
    free(sym);
}

/*******************************************************************************
 * Main functions
 ******************************************************************************/

lib_symbol_list *
lib_syms_init()
{
    lib_symbol_list *new_list = malloc(sizeof(lib_symbol_list));
    new_list->data_count = 0;
    new_list->data = NULL;
    return new_list;
}

void
lib_syms_clean(lib_symbol_list *list)
{
    free(list->data);
    free(list);
}

void
lib_syms_clean_deep(lib_symbol_list *list)
{
    for (size_t i = 0; i < list->data_count; ++i)
    {
        lib_syms_clean_one_entry(list->data[i]);
    }
    lib_syms_clean(list);
}

void
lib_syms_insert(lib_symbol *to_insert, lib_symbol_list *list)
{
    size_t curr_count = list->data_count;
    list->data = realloc(list->data, (curr_count + 1) * sizeof(lib_symbol *));
    if (list->data == NULL)
    {
        err(1, "Error inserting symbol %s in lib_list!", to_insert->sym_name);
    }
    list->data[curr_count] = to_insert;
    list->data_count += 1;
}

lib_symbol *
lib_syms_search(const char *to_find, const lib_symbol_list *list)
{
    for (size_t i = 0; i < list->data_count; ++i)
    {
        if (!strcmp(list->data[i]->sym_name, to_find))
        {
            return list->data[i];
        }
    }
    errx(1, "Did not find symbol %s!\n", to_find);
}

lib_symbol_list *
lib_syms_find_all(const char *to_find, const lib_symbol_list *list)
{
    lib_symbol_list *res = lib_syms_init();
    for (size_t i = 0; i < list->data_count; ++i)
    {
        if (!strcmp(list->data[i]->sym_name, to_find))
        {
            lib_syms_insert(list->data[i], res);
        }
    }
    return res;
}
