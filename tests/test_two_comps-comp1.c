#include <stdio.h>

size_t
call_comp(size_t comp_id, char *fn_name, void *args, size_t arg_count)
{
    return 0;
};

int
inter_call()
{
    size_t call_res = call_comp(1, "main", NULL, 0);
    return 0;
}

int
main()
{
    fprintf(stdout, "Hello, I am comp1.\n");
    return 0;
}
