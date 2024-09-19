#ifndef _CHERICOMP_SYMBOLS_H
#define _CHERICOMP_SYMBOLS_H

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct simple_lds_list
{
    struct LibDependencySymbol **data;
    size_t data_count;
};

struct simple_cs_list
{
    struct CompSymbol **data;
    size_t data_count;
};

typedef struct simple_lds_list lib_symbol_list;
typedef struct LibDependencySymbol lib_symbol;

typedef struct simple_cs_list comp_symbol_list;
typedef struct CompSymbol comp_symbol;

/* Struct representing a symbol entry of a dependency library
 */
struct LibDependencySymbol
{
    char *sym_name;
    void *sym_offset;
    unsigned short sym_type;
    unsigned short sym_bind;
    uint16_t sym_shndx;
};

/* Struct representing a wrapper around a LibDependencySymbol, in order to
 * facilitate compartment-level searching
 */
struct CompSymbol
{
    struct LibDependencySymbol *sym_ref;
    size_t sym_lib_idx;
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
comp_syms_search(const char *, const comp_symbol_list *);
comp_symbol_list *
comp_syms_find_all(const char *, const comp_symbol_list *);

lib_symbol_list *
lib_syms_init();
void
lib_syms_clean(lib_symbol_list *);
void
lib_syms_clean_deep(lib_symbol_list *);
void
lib_syms_insert(lib_symbol *, lib_symbol_list *);
lib_symbol *
lib_syms_search(const char *, const lib_symbol_list *);
lib_symbol_list *
lib_syms_find_all(const char *, const lib_symbol_list *);

#endif // _CHERICOMP_SYMBOLS_H
