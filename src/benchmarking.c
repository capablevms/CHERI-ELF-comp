#include <benchmarking.h>

static size_t next_id = 0;
static struct bench_entry **benchs;

/*******************************************************************************
 * Diff functions
 ******************************************************************************/

static double
timespec_diff(struct timespec *end, struct timespec *start)
{
    return (end->tv_sec - start->tv_sec)
        + (end->tv_nsec - start->tv_nsec) * pow(10, -9);
}

/*******************************************************************************
 * Benchmark one function
 ******************************************************************************/

size_t
bench_init(const char *fn_name)
{
    return 0;
    struct bench_entry *new_be = malloc(sizeof(struct bench_entry));
    new_be->fn_name = fn_name;
    next_id += 1;
    benchs = realloc(benchs, next_id * sizeof(struct bench_entry *));
    benchs[next_id - 1] = new_be;
    return next_id - 1;
}

void
bench_start(size_t id)
{
    return;
    benchs[id]->res_start = clock_gettime(CLOCK_MONOTONIC, &benchs[id]->start);
}

void
bench_end(size_t id)
{
    return;
    int res_end = clock_gettime(CLOCK_MONOTONIC, &benchs[id]->end);
    assert(benchs[id]->res_start != -1);
    assert(res_end != -1);
    benchs[id]->diff = timespec_diff(&benchs[id]->end, &benchs[id]->start);
    bench_report_one_id(id);
}

/*******************************************************************************
 * Printing
 ******************************************************************************/

static void
print_timespec(char *buf, struct timespec *ts)
{
    sprintf(buf, "%lld.%9ld", (long long) ts->tv_sec, ts->tv_nsec);
}

static void
bench_report_one(struct bench_entry *entry)
{

    const unsigned short buf_sz = 30;
    char *buf_st = alloca(buf_sz);
    print_timespec(buf_st, &entry->start);
    char *buf_en = alloca(buf_sz);
    print_timespec(buf_en, &entry->end);
    printf("Func <%s> -- start %s -- end %s -- seconds %f\n", entry->fn_name,
        buf_st, buf_en, entry->diff);
}

void
bench_report_one_id(size_t id)
{
    printf("ID %zu == ", id);
    bench_report_one(benchs[id]);
}
