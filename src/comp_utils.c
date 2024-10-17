#include "comp_utils.h"

static size_t mem_left = 0;
static void *heap_header = NULL;
static void *heap_start = NULL;
const static size_t block_metadata_sz = sizeof(void *) + sizeof(size_t);

#define NON_COMP_DEFAULT_SIZE (1024 * 1024 * 1024) // 1 GB

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

static inline void *
get_next(void *addr)
{
    return *(void **) ((char *) addr - sizeof(void *));
}

static inline size_t
get_size(void *addr)
{
    return *(size_t *) ((char *) addr - block_metadata_sz);
}

static inline size_t
get_next_slot_size(void *addr)
{
    return (size_t) get_next(addr) - (uintptr_t) addr - get_size(addr);
}

static inline void
set_next(void *addr, void *next)
{
    memcpy((char *) addr - sizeof(void *), &next, sizeof(void *));
}

static inline void
set_size(void *addr, size_t size)
{
    memcpy((char *) addr - block_metadata_sz, &size, sizeof(size_t));
}

static inline void
make_new_metadata(void *addr, size_t size, void *next, void *prev)
{
    set_next(addr, next);
    set_size(addr, size);
    if (prev)
    {
        set_next(prev, addr);
    }
}

static inline void
clear_block(void *addr)
{
    memset((char *) addr - block_metadata_sz, 0, get_size(addr));
}

/*******************************************************************************
 * Main functions
 ******************************************************************************/

void *
malloc(size_t to_alloc)
{
    if (!heap_header)
    {
        void *__capability ddc = cheri_ddc_get();
        void *mem_begin;
        if (cheri_base_get(ddc) == 0)
        {
            mem_begin = mmap(0, NON_COMP_DEFAULT_SIZE, PROT_WRITE | PROT_READ,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mem_begin == MAP_FAILED)
            {
                err(1, "comp_utils: Failed `mmap`");
            }
            mem_left = NON_COMP_DEFAULT_SIZE;
        }
        else
        {
            mem_begin = (char *) cheri_address_get(ddc);
            // TODO move heap to the end of the compartment; currently, it's at
            // the beginning of the memory scratch area
            mem_left = cheri_length_get(ddc) - cheri_offset_get(ddc);
        }
        heap_start = (char *) mem_begin + sizeof(size_t) + sizeof(void *);
        heap_header = heap_start;
    }

    /* We put some metadata at the beginning of each allocated block
    // * size_t size
    // * void* next_block
    */
    size_t to_alloc_total = to_alloc + block_metadata_sz;

    if (to_alloc_total > mem_left)
    {
        return NULL;
    }

    // Find a sufficiently large block to allocate
    void *curr_block = heap_header;
    void *prev_block = NULL;
    void *next_to_set = NULL;

    // Check if we have enough space before the first allocated block
    if ((uintptr_t) curr_block - (uintptr_t) heap_start >= to_alloc_total)
    {
        curr_block = heap_start;
        next_to_set = heap_header;
        heap_header = curr_block;
    }
    else
    {
        while (curr_block)
        {
            prev_block = curr_block;
            if (!get_next(curr_block)
                || get_next_slot_size(curr_block) >= to_alloc_total)
            {
                next_to_set = get_next(curr_block);
                curr_block = (char *) curr_block + get_size(curr_block);
                break;
            }
            curr_block = get_next(curr_block);
        }
    }

    if (curr_block == prev_block)
    {
        prev_block = NULL;
    }
    make_new_metadata(curr_block, to_alloc_total, next_to_set, prev_block);

    memset(curr_block, 0, to_alloc);
    mem_left -= to_alloc_total;
    return curr_block;
}

void
free(void *to_free)
{
    if (!to_free)
    {
        return;
    }

    void *curr_block = heap_header;

    if (curr_block == to_free)
    {
        heap_header = get_next(curr_block);
        clear_block(curr_block);
        return;
    }

    while (curr_block)
    {
        if (get_next(curr_block) == to_free)
        {
            void *free_block = get_next(curr_block);
            set_next(curr_block, get_next(free_block));
            clear_block(free_block);
            mem_left += get_size(to_free) + block_metadata_sz;
            return;
        }
        curr_block = get_next(curr_block);
    }
    errx(1, "comp_utils: Did not find block to free for addr `%p`!\n", to_free);
}

void *
calloc(size_t elem_count, size_t elem_size)
{
    return malloc(elem_count * elem_size);
}

void *
realloc(void *to_realloc, size_t new_size)
{
    if (!to_realloc || get_size(to_realloc) == 0)
    {
        return malloc(new_size);
    }

    if (new_size + block_metadata_sz > get_size(to_realloc))
    {
        void *new_alloc = malloc(new_size);
        memcpy(new_alloc, to_realloc, get_size(to_realloc) - block_metadata_sz);
        free(to_realloc);
        mem_left -= new_size - get_size(to_realloc);
        return new_alloc;
    }

    memset((char *) to_realloc + new_size, 0,
        get_size(to_realloc) - new_size - block_metadata_sz);
    set_size(to_realloc, new_size + block_metadata_sz);
    mem_left += get_size(to_realloc) - new_size;
    return to_realloc;
}

void *
reallocarray(void *to_realloc, size_t elem_count, size_t elem_size)
{
    return realloc(to_realloc, elem_count * elem_size);
}

void
tls_lookup_stub()
{
    // Get TLS index
    // TODO works only for one TLS region
#ifdef __CHERI__
    asm("ldr x0, [x0, #8]" : :);
#else
    asm("lea -0x8(%%rbp), %%rcx" : :);
#endif
    return;
}
