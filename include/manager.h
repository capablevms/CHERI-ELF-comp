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

// Third-party libraries
#include "toml.h"

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

/* This function expects the argument be passed in `x10`, rather than `x0`, as
 * well as using `c29` as an argument for the DDC to transition to in order to
 * allow the intercept to work. It is expected to be called only in very
 * specific circumstances, and the signature is more illustrative than
 * functional. As such, it shouldn't be called from a C context, as that will
 * most likely break things.
 */
void intercept_wrapper(void* to_call_fn);

void setup_intercepts();

time_t manager_time(time_t*);
FILE* manager_fopen(const char*, const char*);
size_t manager_fread(void* __restrict, size_t, size_t, FILE* __restrict);
size_t manager_fwrite(void* __restrict, size_t, size_t, FILE* __restrict);
int manager_fclose(FILE*);
int manager_getc(FILE*);
int manager_fputc(int, FILE*);
int manager___srget(FILE*);

void* my_realloc(void*, size_t);
void* my_malloc(size_t);
void my_free(void*);
int my_fprintf(FILE*, const char*, ...);

size_t my_call_comp(size_t, char*, void*, size_t);

static const struct func_intercept to_intercept_funcs[] = {
    /* vDSO funcs */
    { "time"     , (uintptr_t) manager_time    },
    /* Mem funcs */
    { "malloc"   , (uintptr_t) my_malloc       },
    { "realloc"  , (uintptr_t) my_realloc      },
    { "free"     , (uintptr_t) my_free         },
    { "fprintf"  , (uintptr_t) my_fprintf      },
    /* Compartment funcs */
    { "call_comp", (uintptr_t) my_call_comp    },
    /* Other funcs */
    { "fopen"    , (uintptr_t) manager_fopen   },
    { "fread"    , (uintptr_t) manager_fread   },
    { "fwrite"   , (uintptr_t) manager_fwrite  },
    { "fclose"   , (uintptr_t) manager_fclose  },
    { "getc"     , (uintptr_t) manager_getc    },
    { "fputc"    , (uintptr_t) manager_fputc   },
    { "__srget"  , (uintptr_t) manager___srget },
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

// Compartment configuration file suffix
extern const char* comp_config_suffix;

// Capabilities required to transition back into the manager once compartment
// execution has finished
extern void* __capability comp_return_caps[COMP_RETURN_CAPS_COUNT];

struct Compartment* manager_find_compartment_by_addr(void*);
struct Compartment* manager_find_compartment_by_ddc(void* __capability);
struct Compartment* manager_get_compartment_by_id(size_t);

#include "compartment.h"

// TODO stack setup when we transition into the compartment; unsure if needed,
// but keep for now, just in case
#define ENV_FIELDS_CNT 1
extern const char* comp_env_fields[ENV_FIELDS_CNT];
extern char** environ;
const char* get_env_str(const char*);
int manager___vdso_clock_gettime(clockid_t, struct timespec*);
// END TODO

union arg_holder
{
    int i;
    long l;
    char c;
    long long ll;
    unsigned long long ull;
};

char* prep_config_filename(char*);
struct ConfigEntryPoint* parse_compartment_config(char*, size_t*);
void clean_compartment_config(struct ConfigEntryPoint*, size_t);
struct ConfigEntryPoint get_entry_point(char*, struct ConfigEntryPoint*, size_t);
void* prepare_compartment_args(char** args, struct ConfigEntryPoint);
struct ConfigEntryPoint* set_default_entry_point(struct ConfigEntryPoint*);

/*******************************************************************************
 * Memory allocation
 ******************************************************************************/

#include "mem_mng.h"

#endif // _MANAGER_H
