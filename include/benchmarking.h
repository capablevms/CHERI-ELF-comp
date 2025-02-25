#ifndef _BENCHMARKING_COMP_H
#define _BENCHMARKING_COMP_H

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH(name, func)                                                      \
    do                                                                         \
    {                                                                          \
        size_t id = bench_init(name);                                          \
        bench_start(id);                                                       \
        func;                                                                  \
        bench_end(id);                                                         \
    } while (0)

struct bench_entry
{
    const char *fn_name;
    struct timespec start;
    struct timespec end;
    int res_start;
    double diff;
};

size_t
bench_init(const char *);
void bench_start(size_t);
void bench_end(size_t);

void bench_report_one_id(size_t);

#endif // _BENCHMARKING_COMP_H
