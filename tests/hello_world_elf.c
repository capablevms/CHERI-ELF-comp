#include "hello_world_elf.h"

//#define printf my_printf

static const char my_str[13] = "Hello World!";

void
do_print()
{
    printf("My string is hallo welt.\n");
}

void
do_print_args(const char* arg_string)
{
    printf("My arg string is %s.\n", arg_string);
}

int
main()
{
    do_print();
    return 0;
    /*printf("My String is %s.\n", my_str);*/
    /*do_print();*/
    /*do_print_args(my_str);*/
    /*return 0;*/
}
