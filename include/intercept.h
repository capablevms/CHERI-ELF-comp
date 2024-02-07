#ifndef _INTERCEPT_H
#define _INTERCEPT_H

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>

// vDSO wrapper needed includes
#include <time.h>

#include "cheriintrin.h"

#include "mem_mng.h"

// Forward declarations
struct Compartment;
extern struct Compartment* loaded_comp;
int64_t exec_comp(struct Compartment*, char*, char**);
struct Compartment* manager_get_compartment_by_id(size_t);

extern void* __capability manager_ddc;

// Number of capabilities required to perform a transition
#define COMP_RETURN_CAPS_COUNT 2

// Capabilities required to transition back into the manager once compartment
// execution has finished
extern void* __capability comp_return_caps[COMP_RETURN_CAPS_COUNT];

// Capability used to point to pair of capabilities when transitioning out of a
// compartment via an intercept
extern void* __capability sealed_redirect_cap;

/* Data required to perform the transition for an intercepted function
 */
struct func_intercept {
    char* func_name;
    void* redirect_func;
    void* __capability intercept_pcc;
};

/* This function expects the argument be passed in `x10`, rather than `x0`, as
 * well as using `c29` as an argument for the DDC to transition to in order to
 * allow the intercept to work. It is expected to be called only in very
 * specific circumstances, and the signature is more illustrative than
 * functional. As such, it shouldn't be called from a C context, as that will
 * most likely break things.
 */
void intercept_wrapper();

void setup_intercepts();

time_t intercepted_time(time_t*);
FILE* intercepted_fopen(const char*, const char*);
size_t intercepted_fread(void* __restrict, size_t, size_t, FILE* __restrict);
size_t intercepted_fwrite(void* __restrict, size_t, size_t, FILE* __restrict);
int intercepted_fclose(FILE*);
int intercepted_getc(FILE*);
int intercepted_fputc(int, FILE*);
int intercepted___srget(FILE*);

void* my_realloc(void*, size_t);
void* my_malloc(size_t);
void my_free(void*);
int my_fprintf(FILE*, const char*, ...);

size_t my_call_comp(size_t, char*, void*, size_t);
static const struct func_intercept to_intercept_funcs[] = {
    /* vDSO funcs */
    { "time"     , (void*) intercepted_time    },
    /* Mem funcs */
    { "malloc"   , (void*) my_malloc       },
    { "realloc"  , (void*) my_realloc      },
    { "free"     , (void*) my_free         },
};
//
// Functions to be intercepted and associated data
#define INTERCEPT_FUNC_COUNT sizeof(to_intercept_funcs) / sizeof(to_intercept_funcs[0])
extern struct func_intercept comp_intercept_funcs[INTERCEPT_FUNC_COUNT];

#endif // _INTERCEPT_H
