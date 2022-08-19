.text
.balign 4

/* Wrapper to an intercept function, executed within a manager context;
 * required in order to maintain a consisten execution state. This also manages
 * setting the `DDC` as needed.
 */
.global intercept_wrapper
.type intercept_wrapper, "function"
intercept_wrapper:
    stp c28, c29, [sp, #-64]!
    mrs c28, ddc
    msr ddc, c29
    stp clr, c28, [sp, #32]
    blr x10
    ldp clr, c28, [sp, #32]
    msr ddc, c28
    ldp c28, c29, [sp], #64
    ret

/* Function to transition out of a compartment; essentially the `ldpblr`
 * transition instruction, and some book-keeping.
 */
.global compartment_transition_out
.type compartment_transition_out, "function"
compartment_transition_out:
    stp c29, clr, [sp, #-32]!
    ldpblr c29, [c11]
    ldp c29, clr, [sp], #32
    ret
compartment_transition_out_end:

/* comp_exec_in(void* comp_sp, void* __capability comp_ddc, void* fn) */
/* Instructions to enter a compartment. There is no `ret`, as we need to
 * perform a context switch upon exiting, which is done via `ldpbr`
 */
.global comp_exec_in
.type comp_exec_in, "function"
comp_exec_in:
    stp lr, x29, [sp, #-16]!
    mov x19, sp

    mov sp, x0
    msr DDC, c1
    blr x2

    adr x11, comp_return_caps
    cvtp c11, x11
    ldpbr c29, [c11]

/* Instructions to perform once a compartment has finished execution.
 *
 * Expects `DDC` in c29, resets `sp` and `clr` to continue execution for the
 * manager. The result of the compartment is expected in `x0`.
 */
.global comp_exec_out
.type comp_exec_out, "function"
comp_exec_out:
    msr DDC, c29
    mov sp, x19
    ldp lr, x29, [sp], #16
    ret
