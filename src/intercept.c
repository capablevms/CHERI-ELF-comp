#include "intercept.h"

void *__capability comp_return_caps[COMP_RETURN_CAPS_COUNT];
void *__capability sealed_redirect_cap;

/* Setup required capabilities on the heap to jump from within compartments via
 * a context switch
 *
 * For each function to be intercepted, we define the following:
 * redirect_func function to be executed at a higher privilege level
 * TODO I think the below three are common and can be lifted
 * intercept_ddc ddc to be installed for the transition
 * intercept_pcc
 *      higher privileged pcc pointing to the transition support function
 * sealed_redirect_cap
 *      sealed capability pointing to the consecutive intercept capabilities;
 *      this is the only component visible to the compartments
 */
void
setup_intercepts()
{
    sealed_redirect_cap = manager_ddc;
    sealed_redirect_cap
        = cheri_address_set(sealed_redirect_cap, (intptr_t) comp_return_caps);
    asm("SEAL %[cap], %[cap], lpb\n\t"
        : [cap] "+C"(sealed_redirect_cap)
        : /**/);
    comp_return_caps[0] = manager_ddc; // TODO does this need to be sealed?
    comp_return_caps[1]
        = cheri_address_set(cheri_pcc_get(), (uintptr_t) comp_exec_out);
}

size_t
my_call_comp(
    size_t comp_id, char *fn_name, void *args) // TODO , size_t args_count)
{
    struct Compartment *to_call = manager_get_compartment_by_id(comp_id);
    return exec_comp(to_call, fn_name, args);
    /*return exec_comp(to_call, fn_name, args, args_count);*/
}
