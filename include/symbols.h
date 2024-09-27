#ifndef _CHERICOMP_SYMBOLS_H
#define _CHERICOMP_SYMBOLS_H

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tommy.h"

#define HASHTABLE_MAX_SZ 1024
#define hashtable_hash(x) tommy_hash_u64(0, x, strlen(x))

#define MAX_FIND_ALL_COUNT 1024

#endif // _CHERICOMP_SYMBOLS_H
