#ifndef _INTERCEPT_H
#define _INTERCEPT_H

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

// vDSO wrapper needed includes
#include <time.h>

#ifdef __CHERI__
#include "cheriintrin.h"
#endif

// Forward declarations
struct Compartment;
extern struct Compartment *loaded_comp;
int64_t
exec_comp(struct Compartment *, char *, char **);
struct Compartment *manager_get_compartment_by_id(size_t);

extern void *__capability manager_ddc;
extern void
comp_exec_out(void);

// Number of capabilities required to perform a transition
#define COMP_RETURN_CAPS_COUNT 2

// Capabilities required to transition back into the manager once compartment
// execution has finished
extern void *__capability comp_return_caps[COMP_RETURN_CAPS_COUNT];

// Capability used to point to pair of capabilities when transitioning out of a
// compartment via an intercept
extern void *__capability sealed_redirect_cap;

/* Data required to perform the transition for an intercepted function
 */
struct FuncIntercept
{
    char *func_name;
    void *redirect_func;
    void *__capability intercept_pcc;
};

/* This function expects the argument be passed in `x10`, rather than `x0`, as
 * well as using `c29` as an argument for the DDC to transition to in order to
 * allow the intercept to work. It is expected to be called only in very
 * specific circumstances, and the signature is more illustrative than
 * functional. As such, it shouldn't be called from a C context, as that will
 * most likely break things.
 */
void
intercept_wrapper(void);

void
setup_intercepts(void);

// TODO Reimplement this for inter-compartment function calls
// size_t
// my_call_comp(size_t, char *, void *);

#endif // _INTERCEPT_H
