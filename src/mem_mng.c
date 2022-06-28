#include "mem_mng.h"

// MEM TODO

void*
manager_register_mem_alloc(struct Compartment* comp, size_t mem_size)
{
    // TODO better algorithm to find blocks of memory available for mapping
    void* new_mem = mmap((void*) (comp->scratch_mem_base + comp->scratch_mem_alloc),
                         mem_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS,
                         -1, 0);

    struct mem_alloc* new_alloc = malloc(sizeof(struct mem_alloc));
    new_alloc->ptr = (uintptr_t) new_mem;
    new_alloc->size = mem_size;
    manager_insert_new_alloc(comp, new_alloc);
    return new_mem;
}

void
manager_insert_new_alloc(struct Compartment* comp, struct mem_alloc* to_insert)
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

    struct mem_alloc* curr_alloc = comp->alloc_head;
    while(curr_alloc->next_alloc != NULL && curr_alloc->ptr < to_insert->ptr)
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
manager_free_mem_alloc(struct Compartment* comp, void* ptr)
{
    struct mem_alloc* curr_alloc = comp->alloc_head;
    while (curr_alloc != NULL && curr_alloc->ptr != (uintptr_t) ptr)
    {
        curr_alloc = curr_alloc->next_alloc;
    }

    assert(curr_alloc != NULL && "Memory allocation not found to be freed.");
    size_t munmap_res = munmap((void*) curr_alloc->ptr, curr_alloc->size);
    assert(munmap_res == 0);
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
    // TODO subtract allocated memory

    return to_return;
}
