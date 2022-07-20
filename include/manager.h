#ifndef _MANAGER_H
#define _MANAGER_H

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/auxv.h>
#include <stdarg.h>
#include <stdio.h>

// vDSO wrapper needed includes
#include <sys/time.h>

extern void* __capability manager_ddc;

/*******************************************************************************
 * Intercepts
 ******************************************************************************/

/* Data required to perform the transition for an intercepted function
 */
struct func_intercept {
    char* func_name;
    uintptr_t redirect_func;
    void* __capability intercept_ddc;
    void* __capability intercept_pcc;
    void* __capability redirect_cap;
};

/* This function expects the argument be passed in `x10`, rather than `x0`. It
 * is expected to be called only in very specific circumstances, and the
 * signature is more illustrative than functional. As such, it shouldn't be
 * called from a C context, as that will most likely break things.
 */
void intercept_wrapper(void* to_call_fn);

void setup_intercepts();

time_t manager_time(time_t*);
void* my_realloc(void*, size_t);
void* my_malloc(size_t);
void my_free(void*);
int my_fprintf(FILE*, const char*, ...);

static const struct func_intercept to_intercept_funcs[] = {
    /* vDSO funcs */
    { "time", (uintptr_t) manager_time },
    /* Mem funcs */
    { "malloc", (uintptr_t) my_malloc },
    { "realloc", (uintptr_t) my_realloc },
    { "free", (uintptr_t) my_free },
    { "fprintf", (uintptr_t) my_fprintf },
};
//
// Functions to be intercepted and associated data
#define INTERCEPT_FUNC_COUNT sizeof(to_intercept_funcs) / sizeof(to_intercept_funcs[0])
extern struct func_intercept comp_intercept_funcs[INTERCEPT_FUNC_COUNT];

/*******************************************************************************
 * Utility Functions
 ******************************************************************************/

void print_full_cap(uintcap_t);

/*******************************************************************************
 * Compartment
 ******************************************************************************/

// Number of capabilities required to perform a transition
#define COMP_RETURN_CAPS_COUNT 2

// Capabilities required to transition back into the manager once compartment
// execution has finished
extern void* __capability comp_return_caps[COMP_RETURN_CAPS_COUNT];

struct Compartment* manager_find_compartment_by_addr(void*);
struct Compartment* manager_find_compartment_by_ddc(void* __capability);

#include "compartment.h"

// TODO stack setup when we transition into the compartment; unsure if needed,
// but keep for now, just in case
#define ENV_FIELDS_CNT 1
extern const char* comp_env_fields[ENV_FIELDS_CNT];
extern char** environ;
const char* get_env_str(const char*);
int manager___vdso_clock_gettime(clockid_t, struct timespec*);
// END TODO

/*******************************************************************************
 * Memory allocation
 ******************************************************************************/

#include "mem_mng.h"

#endif // _MANAGER_H
