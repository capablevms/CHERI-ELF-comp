#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

const size_t max_heap_size = 2 * 1024 * 1024;
const size_t malloc_block_sz = 0x10;

int
main(void)
{
    void *x = malloc(max_heap_size - malloc_block_sz);
    void *y = malloc(malloc_block_sz);
    if (y == NULL)
    {
        printf("Memory saturated.\n");
    }

    free(x);
    free(y);
}
