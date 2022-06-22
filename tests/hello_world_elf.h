#ifndef HELLO_WORLD_ELF_H
#define HELLO_WORLD_ELF_H

#include <assert.h>
#include <dlfcn.h>
#include <elf.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void do_print();
void do_print_args(const char*);

void
my_printf(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    printf("my_printf says:\n");
    vprintf(format, args);
    va_end(args);
}

#endif // HELLO_WORLD_ELF_H
