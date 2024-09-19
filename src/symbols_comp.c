#include "symbols.h"

/*******************************************************************************
 * Main functions
 ******************************************************************************/

comp_symbol_list *
comp_syms_init()
{
    comp_symbol_list *new_list = malloc(sizeof(comp_symbol_list));
    new_list->data_count = 0;
    new_list->data = NULL;
    return new_list;
}

void
comp_syms_clean(comp_symbol_list *list)
{
    free(list->data);
    free(list);
}

void
comp_syms_clean_deep(comp_symbol_list *list)
{
    for (size_t i = 0; i < list->data_count; ++i)
    {
        free(list->data[i]);
    }
    comp_syms_clean(list);
}

void
comp_syms_insert(comp_symbol *to_insert, comp_symbol_list *list)
{
    size_t curr_count = list->data_count;
    list->data = realloc(list->data, (curr_count + 1) * sizeof(comp_symbol *));
    if (list->data == NULL)
    {
        err(1, "Error inserting symbol %s in comp_list!",
            to_insert->sym_ref->sym_name);
    }
    list->data[curr_count] = to_insert;
    list->data_count += 1;
}

comp_symbol *
comp_syms_search(const char *to_find, const comp_symbol_list *list)
{
    for (size_t i = 0; i < list->data_count; ++i)
    {
        if (!strcmp(list->data[i]->sym_ref->sym_name, to_find))
        {
            return list->data[i];
        }
    }
    errx(1, "Did not find symbol %s!\n", to_find);
}

comp_symbol_list *
comp_syms_find_all(const char *to_find, const comp_symbol_list *list)
{
    comp_symbol_list *res = comp_syms_init();
    for (size_t i = 0; i < list->data_count; ++i)
    {
        if (!strcmp(list->data[i]->sym_ref->sym_name, to_find))
        {
            comp_syms_insert(list->data[i], res);
        }
    }
    return res;
}
