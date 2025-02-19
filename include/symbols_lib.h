#ifndef _CHERICOMP_SYMBOLS_LIB_H
#define _CHERICOMP_SYMBOLS_LIB_H

#include "symbols.h"

typedef tommy_hashtable lib_symbol_list;
typedef struct LibDependencySymbol lib_symbol;

/* Struct representing a symbol entry of a dependency library
 */
struct LibDependencySymbol
{
    char *sym_name;
    void *sym_offset;
    unsigned short sym_type;
    unsigned short sym_bind;
    uint16_t sym_shndx;
    tommy_node node;
};

lib_symbol_list *
lib_syms_init(void);
void
lib_syms_clean(lib_symbol_list *);
void
lib_syms_clean_deep(lib_symbol_list *);
void
lib_syms_insert(lib_symbol *, lib_symbol_list *);
lib_symbol *
lib_syms_search(const char *, lib_symbol_list *);
lib_symbol **
lib_syms_find_all(const char *, lib_symbol_list *);
void
lib_syms_print(lib_symbol_list *);

#endif // _CHERICOMP_SYMBOLS_LIB_H
