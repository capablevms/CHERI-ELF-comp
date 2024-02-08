#include "mem_mng.h"

// MEM TODO

/* An initial design of a simple bump allocator. This is here more to have
 * something intercept `malloc` calls from the compartment, and might be
 * scrapped in favour of something useful. The only requirement is that we are
 * able to restrict what area of the memory we want to manage to the
 * compartment scratch memory space
 */

void *
manager_register_mem_alloc(struct Compartment *comp, size_t mem_size)
{
    // TODO better algorithm to find blocks of memory available for mapping
    void *new_mem = (char *) comp->scratch_mem_base + comp->scratch_mem_alloc;
    struct MemAlloc *new_alloc = malloc(sizeof(struct MemAlloc));
    new_alloc->ptr = (uintptr_t) new_mem;
    new_alloc->size = mem_size;
    manager_insert_new_alloc(comp, new_alloc);
    comp->scratch_mem_alloc += __builtin_align_up(mem_size, sizeof(void *));
    return new_mem;
}

void
manager_insert_new_alloc(struct Compartment *comp, struct MemAlloc *to_insert)
{
    if (comp->alloc_head == NULL)
    {
        to_insert->prev_alloc = NULL;
        to_insert->next_alloc = NULL;
        comp->alloc_head = to_insert;
        return;
    }

    if (comp->alloc_head->ptr > to_insert->ptr)
    {
        to_insert->next_alloc = comp->alloc_head;
        to_insert->prev_alloc = NULL;
        comp->alloc_head->prev_alloc = to_insert;
        comp->alloc_head = to_insert;
        return;
    }

    struct MemAlloc *curr_alloc = comp->alloc_head;
    while (curr_alloc->next_alloc != NULL && curr_alloc->ptr < to_insert->ptr)
    {
        curr_alloc = curr_alloc->next_alloc;
    }
    if (curr_alloc->next_alloc == NULL)
    {
        to_insert->prev_alloc = curr_alloc;
        curr_alloc->next_alloc = to_insert;
        to_insert->next_alloc = NULL;
        return;
    }

    to_insert->next_alloc = curr_alloc->next_alloc;
    to_insert->next_alloc->prev_alloc = to_insert;
    curr_alloc->next_alloc = to_insert;
    to_insert->prev_alloc = curr_alloc;
    return;
}

size_t
manager_free_mem_alloc(struct Compartment *comp, void *ptr)
{
    struct MemAlloc *curr_alloc = comp->alloc_head;
    while (curr_alloc != NULL && curr_alloc->ptr != (uintptr_t) ptr)
    {
        curr_alloc = curr_alloc->next_alloc;
    }

    assert(curr_alloc != NULL && "Memory allocation not found to be freed.");
    if (curr_alloc->prev_alloc != NULL)
    {
        curr_alloc->prev_alloc->next_alloc = curr_alloc->next_alloc;
    }
    if (curr_alloc->next_alloc != NULL)
    {
        curr_alloc->next_alloc->prev_alloc = curr_alloc->prev_alloc;
    }
    size_t to_return = curr_alloc->size;
    free(curr_alloc);

    return to_return;
}

/**
 * Find allocation record in a compartment for a given address
 *
 * Given a compartment and an address, iterates over the memory allocations
 * recorded for that compartment in order to find the allocation record
 * refering to the given address.
 * This currently expects the allocation record to exactly point to a given
 * address to be searched, due to how the memory allocator is designed.
 *
 * \param comp Compartment in which we expect the allocation to exist
 * \param ptr Address to search for
 * \return A record indicating the requested memory allocation
 */
struct MemAlloc *
get_alloc_struct_from_ptr(struct Compartment *comp, uintptr_t ptr)
{
    struct MemAlloc *curr_alloc = comp->alloc_head;
    while (curr_alloc->next_alloc != NULL)
    {
        if (curr_alloc->ptr == ptr)
        {
            return curr_alloc;
        }
        curr_alloc = curr_alloc->next_alloc;
    }
    errx(1, "ERROR: Could not find allocated pointer %Pu!\n", ptr);
}
