#ifndef MEM_MNG_H
#define MEM_MNG_H

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <cheriintrin.h>

#include "compartment.h"

// TODO consider single linked list
struct mem_alloc
{
    uintptr_t ptr;
    size_t size;

    struct mem_alloc* prev_alloc;
    struct mem_alloc* next_alloc;
};

extern size_t comp_mem_alloc;
extern size_t comp_mem_max;

void* manager_register_mem_alloc(struct Compartment*, size_t);
void manager_insert_new_alloc(struct Compartment*, struct mem_alloc*);
size_t manager_free_mem_alloc(struct Compartment*, void*);
struct mem_alloc* get_alloc_struct_from_ptr(struct Compartment*, uintptr_t);

#endif // MEM_MNG_H
