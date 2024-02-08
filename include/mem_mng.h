#ifndef MEM_MNG_H
#define MEM_MNG_H

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <cheriintrin.h>

#include "compartment.h"

// TODO consider single linked list
struct MemAlloc
{
    uintptr_t ptr;
    size_t size;

    struct MemAlloc *prev_alloc;
    struct MemAlloc *next_alloc;
};

extern size_t comp_mem_alloc;
extern size_t comp_mem_max;

void *
manager_register_mem_alloc(struct Compartment *, size_t);
void
manager_insert_new_alloc(struct Compartment *, struct MemAlloc *);
size_t
manager_free_mem_alloc(struct Compartment *, void *);
struct MemAlloc *
get_alloc_struct_from_ptr(struct Compartment *, uintptr_t);

#endif // MEM_MNG_H
