#include "mappings.h"

/*******************************************************************************
 * Forward static declarations
 ******************************************************************************/

static int
mappings_compare(const void *, const void *);
static void
mappings_clean_one(void *);

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

static int
mappings_compare(const void *arg, const void *item)
{
    const struct CompMapping *arg_entry = (const struct CompMapping *) arg;
    const mapping_entry *item_entry = (const mapping_entry *) item;
    if (item_entry->map_ref->id == arg_entry->id
        && item_entry->map_ref->comp == arg_entry->comp)
    {
        return 0;
    }
    return 1;
}

static void
mappings_clean_one(void *entry)
{
    free(entry);
}

/*******************************************************************************
 * Main functions
 ******************************************************************************/

mappings_list *
mappings_init(void)
{
    mappings_list *new_list = malloc(sizeof(mappings_list));
    tommy_hashtable_init(new_list, MAPPINGS_MAX_SZ);
    return new_list;
}

void
mappings_clean(mappings_list *list)
{
    tommy_hashtable_done(list);
    free(list);
}

void
mappings_clean_deep(mappings_list *list)
{
    tommy_hashtable_foreach(list, mappings_clean_one);
    mappings_clean(list);
}

void
mappings_insert(mapping_entry *to_insert, mappings_list *list)
{
    tommy_hashtable_insert(list, &to_insert->node, to_insert,
        mapping_hash(to_insert->map_ref->comp->id));
}

struct CompMapping *
mappings_search_free(struct Compartment *to_search, mappings_list *list)
{
    tommy_hashtable_node *search_bucket
        = tommy_hashtable_bucket(list, mapping_hash(to_search->id));
    while (search_bucket)
    {
        struct CompMapping *cm
            = ((mapping_entry *) search_bucket->data)->map_ref;
        if (cm->comp == to_search && !cm->in_use)
        {
            return cm;
        }
        search_bucket = search_bucket->next;
    }
    return NULL;
}

void
mappings_delete(struct CompMapping *to_delete, mappings_list *list)
{
    if (tommy_hashtable_remove(list, mappings_compare, to_delete,
            mapping_hash(to_delete->comp->id))
        == 0)
    {
        errx(1, "Unable to find mapping id %zu (for comp %zu) to remove!",
            to_delete->id, to_delete->comp->id);
    }
}
