#ifndef _COMP_UTILS_H
#define _COMP_UTILS_H

#include <err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "cheriintrin.h"

void *malloc(size_t);
void
free(void *);
void *calloc(size_t, size_t);
void *
realloc(void *, size_t);

#endif // _COMP_UTILS_H
