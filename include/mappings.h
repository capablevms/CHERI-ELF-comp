#ifndef _CHERICOMP_MAPPINGS_H
#define _CHERICOMP_MAPPINGS_H

#include <err.h>

#include "compartment.h"

/*******************************************************************************
 * Compartment mappings
 ******************************************************************************/

struct CompMapping
{
    size_t id;
    void *__capability ddc;
    void *map_addr;
    struct Compartment *comp;
    bool in_use;
};

struct CompMapping *
mapping_new(struct Compartment *);
struct CompMapping *
mapping_new_fixed(struct Compartment *, void *);
void
mapping_free(struct CompMapping *);
int64_t
mapping_exec(struct CompMapping *, char *, char **);

/*******************************************************************************
 * Mappings list
 ******************************************************************************/

#include "tommy.h"

#define mapping_hash(x) tommy_inthash_u64(x)
#define MAPPINGS_MAX_SZ 1024

struct CompMappingEntry
{
    struct CompMapping *map_ref;
    tommy_node node;
};

typedef tommy_hashtable mappings_list;
typedef struct CompMappingEntry mapping_entry;
extern mappings_list *mappings;

mappings_list *
mappings_init(void);
void
mappings_clean(mappings_list *);
void
mappings_clean_deep(mappings_list *);
void
mappings_insert(mapping_entry *, mappings_list *);
struct CompMapping *
mappings_search_free(struct Compartment *, mappings_list *);
void
mappings_delete(struct CompMapping *, mappings_list *);

#endif // _CHERICOMP_MAPPINGS_H
