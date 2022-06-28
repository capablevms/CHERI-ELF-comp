#ifndef _MANAGER_H
#define _MANAGER_H

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/auxv.h>

// vDSO wrapper needed includes
#include <sys/time.h>

/*******************************************************************************
 * Compartment
 ******************************************************************************/

#define MAX_INTERCEPT_COUNT 4
#define COMP_RETURN_CAPS_COUNT 2

#include "compartment.h"

#define ENV_FIELDS_CNT 1
extern const char* comp_env_fields[ENV_FIELDS_CNT];
extern char** environ;
extern void* __capability comp_return_caps[COMP_RETURN_CAPS_COUNT];

const char* get_env_str(const char*);
int manager___vdso_clock_gettime(clockid_t, struct timespec*);

struct Compartment* manager_find_compartment_by_addr(void*);
struct Compartment* manager_find_compartment_by_ddc(void* __capability);

/*******************************************************************************
 * Memory allocation
 ******************************************************************************/

#include "mem_mng.h"

extern void* __capability manager_ddc;

void* my_realloc(void*, size_t);
void* my_malloc(size_t);
void my_free(void* ptr);

/*******************************************************************************
 * Compartment function intercepts
 ******************************************************************************/

struct func_intercept {
    char* func_name;
    uintptr_t redirect_func;
    void* __capability intercept_ddc;
    void* __capability intercept_pcc;
    void* __capability redirect_cap;
};

void setup_intercepts();
void print_full_cap(uintcap_t);
void intercept_wrapper(void* to_call_fn);

// Intercept functions
time_t manager_time();

static const struct func_intercept to_intercept_funcs[] = {
    /* vDSO funcs */
    { "time", (uintptr_t) manager_time },
    //"printf",
    /* Mem funcs */
    //{ "malloc", (uintptr_t) my_malloc },
    //{ "realloc", (uintptr_t) my_realloc },
    //{ "free", (uintptr_t) my_free },
};
#define INTERCEPT_FUNC_COUNT sizeof(to_intercept_funcs) / sizeof(to_intercept_funcs[0])
extern struct func_intercept comp_intercept_funcs[INTERCEPT_FUNC_COUNT];

#endif // _MANAGER_H
