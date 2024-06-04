#include "comp_utils.h"

static void *malloc_ptr;
static size_t heap_mem_left;

#define NON_COMP_DEFAULT_SIZE (10 * 1024) // 10 MB

void *
malloc(size_t to_alloc)
{
    if (!malloc_ptr)
    {
        void *__capability ddc = cheri_ddc_get();
        if (cheri_base_get(ddc) == 0)
        {
            malloc_ptr = mmap(0, NON_COMP_DEFAULT_SIZE, PROT_WRITE | PROT_READ,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            heap_mem_left = NON_COMP_DEFAULT_SIZE;
            if (malloc_ptr == MAP_FAILED)
            {
                err(1, "Failed `mmap`");
            }
        }
        else
        {
            malloc_ptr = (char *) cheri_address_get(ddc);
            // TODO move heap to the end of the compartment; currently, it's at
            // the beginning of the memory scratch area
            heap_mem_left = cheri_length_get(ddc) - cheri_offset_get(ddc);
        }
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

void
tls_lookup_stub()
{
    // Get TLS index
    // TODO works only for one TLS region
    asm("ldr x0, [x0, #8]" : :);
    return;
}
