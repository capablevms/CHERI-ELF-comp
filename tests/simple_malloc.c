#include <assert.h>
#include <stdlib.h>
#include <string.h>

static inline void
check_next(void *addr, void *to_check)
{
    assert(*((void **) ((char *) addr - sizeof(void *))) == to_check);
}

static void
double_val(int *v)
{
    *v = *v * 2;
}

int
main(void)
{
    const char *hw = "Hello World!";
    const size_t hw_sz = strlen(hw);

    char *x = malloc(hw_sz + 1);
    strcpy(x, hw);
    assert(!strcmp(x, "Hello World!"));

    x = realloc(x, hw_sz * 2 + 1);
    strcat(x, hw);
    assert(!strcmp(x, "Hello World!Hello World!"));

    x = realloc(x, hw_sz + 1);
    x[strlen(hw)] = '\0';
    assert(!strcmp(x, "Hello World!"));

    free(x);

    const size_t malloc_block_sz = 16;

    // Check free
    void *tmp01 = malloc(2 * malloc_block_sz);
    void *tmp02 = malloc(1 * malloc_block_sz);
    free(tmp01);
    tmp01 = malloc(2 * malloc_block_sz);
    free(tmp02);
    free(tmp01);

    // Check stack and heap disjointment
    int *int01 = malloc(1 * sizeof(int));
    *int01 = 42;
    double_val(int01);
    assert(*int01 == 84);
    free(int01);

    // Check realloc
    void *tmp11 = realloc(NULL, 2 * malloc_block_sz);
    void *tmp13 = realloc(NULL, 1 * malloc_block_sz);
    void *tmp12 = realloc(tmp11, 2 * malloc_block_sz);

    assert(tmp11 == tmp12);

    void *tmp14 = realloc(tmp12, 4 * malloc_block_sz);
    check_next(tmp13, tmp14);

    void *tmp15 = malloc(2 * malloc_block_sz);
    check_next(tmp15, tmp13);

    free(tmp13);
    check_next(tmp15, tmp14);
    free(tmp15);
    free(tmp14);

    // Check finding right block to insert
    void *tmp1 = malloc(1 * malloc_block_sz);
    void *y = malloc(3 * malloc_block_sz);
    void *tmp2 = malloc(1 * malloc_block_sz);
    void *tmp3 = malloc(5 * malloc_block_sz);
    free(y);
    void *tmp4 = malloc(malloc_block_sz);
    void *tmp5 = malloc(malloc_block_sz);

    assert(tmp1 < tmp4);
    assert(tmp1 < tmp5);
    assert(tmp4 < tmp2);
    assert(tmp5 < tmp2);

    free(tmp1);
    free(tmp2);
    free(tmp3);
    free(tmp4);
    free(tmp5);

    return 0;
}
