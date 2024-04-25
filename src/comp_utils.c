#include "comp_utils.h"

static void *malloc_ptr;
static size_t heap_mem_left;

void *
malloc(size_t to_alloc)
{
    if (!malloc_ptr)
    {
        void *__capability ddc = cheri_ddc_get();
        malloc_ptr = (char *) cheri_address_get(ddc);
        heap_mem_left = cheri_length_get(ddc) - cheri_offset_get(ddc);
    }
    if (to_alloc > heap_mem_left)
    {
        errx(1, "Insufficient heap space left.");
    }
    void *to_ret = malloc_ptr;
    memset(to_ret, 0, to_alloc);
    malloc_ptr = (char *) malloc_ptr + to_alloc;
    heap_mem_left -= to_alloc;
    return to_ret;
}

void
free(void *to_free)
{
    // TODO temp usage for bump allocator implementation to satisfy compiler
    to_free = to_free;
}

void *
calloc(size_t elem_count, size_t elem_size)
{
    return malloc(elem_count * elem_size);
}

void *
realloc(void *to_realloc, size_t new_size)
{
    // TODO temp usage for bump allocator implementation to satisfy compiler
    to_realloc = to_realloc;

    return malloc(new_size);
}
