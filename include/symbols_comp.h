#ifndef _CHERICOMP_SYMBOLS_COMP_H
#define _CHERICOMP_SYMBOLS_COMP_H

#include "symbols.h"
#include "symbols_lib.h"

typedef tommy_hashtable comp_symbol_list;
typedef struct CompSymbol comp_symbol;

/* Struct representing a wrapper around a LibDependencySymbol, in order to
 * facilitate compartment-level searching
 */
struct CompSymbol
{
    struct LibDependencySymbol *sym_ref;
    size_t sym_lib_idx;
    tommy_node node;
};

comp_symbol_list *
comp_syms_init();
void
comp_syms_clean(comp_symbol_list *);
void
comp_syms_clean_deep(comp_symbol_list *);
void
comp_syms_insert(comp_symbol *, comp_symbol_list *);
comp_symbol *
comp_syms_search(const char *, comp_symbol_list *);
comp_symbol **
comp_syms_find_all(const char *, comp_symbol_list *);
void
comp_syms_print(comp_symbol_list *);

void
update_comp_syms(comp_symbol_list *, lib_symbol_list *, const size_t);

#endif // _CHERICOMP_SYMBOLS_COMP_H
