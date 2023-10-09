.text
.balign 4

/* Wrapper to an intercept function, executed within a manager context;
 * required in order to maintain a consistent execution state. This also manages
 * setting the `DDC` as needed.
 *
 * This function takes `x10` as argument, pointing to the address to jump to
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
    // TODO
    stp c29, clr, [sp, #-32]!
    ldpblr c29, [c11]
    ldp c29, clr, [sp], #32
    ret
compartment_transition_out_end:

/* comp_exec_in(void* comp_sp, void* __capability comp_ddc, void* fn,
                void* args, size_t args_count,
                void* __capability sealed_redirect_cap) */
/* Instructions to enter a compartment. There is no `ret`, as we need to
 * perform a context switch upon exiting, which is done via `ldpbr`
 */
.global comp_exec_in
.type comp_exec_in, "function"
comp_exec_in:
    /* Store data required to be restored later
    /  - `x19` is callee-saved, used to hold the stack pointer between
         `comp_exec_in` and `comp_exec_out`
       - `lr` is used to remember where we came from, so we can return
       - `x29` is the frame-pointer, to be restored on exit

       Stack layout:
       `SP + 5 * 8` -->  ---------------------
       `SP + 4 * 8` --> |      <PADDING>      |
       `SP + 3 * 8`   > |       old x29       |
       `SP + 2 * 8`   > |       old  LR       |
       `SP + 1 * 8`   > |  callee-saved  x19  |
       `    new SP`   >  ---------------------
    */
    stp x19, lr, [sp, #-32]!
    str x29, [sp, #16]
    mov x19, sp

    // Move arguments to temporary registers (we'll need them later)
    mov x9, x0
    mov c10, c1
    mov x11, x2
    mov c20, c5

    // Load params (only handle 3 params):
    // TODO increase to 6
loading_params:
    cbz  x4, loaded_params // Check if we loaded all parameters
    bl   load_param
    mov  x0, x5       // Store one argument

    cbz  x4, loaded_params
    bl   load_param
    mov  x1, x5

    cbz  x4, loaded_params
    bl   load_param
    mov  x2, x5
    b    loaded_params

load_param:
    ldr  x5, [x3]
    add  x3, x3, #8
    sub  x4, x4, #1
    ret

loaded_params:
    // Clean
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr

    // Transition into new compartment
    mov sp, x9
    msr DDC, c10
    // We are now fully in the new context

    // Save capability needed to restore context
    // TODO I think this should be somewhere within the compartment
    str c20, [sp, #-32]!

    // Call required function within compartment
    blr x11

    ldr c11, [sp]
    ldpbr c29, [c11]

/* Instructions to perform once a compartment has finished execution.
 *
 * Expects `DDC` in c29, resets `sp` and `clr` to continue execution for the
 * manager. The result of the compartment is expected in `x0`.
 *
 * This function should only be called from `comp_exec_in`, after the
 * compartment has finished executing.
 */
.global comp_exec_out
.type comp_exec_out, "function"
comp_exec_out:
    msr DDC, c29
    mov sp, x19
    ldp x19, lr, [sp], #32
    ldr x29, [sp, #-16]
    ret
