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

/* comp_exec_in(void* comp_sp, void* __capability comp_ddc, void* fn,
                void* args, size_t args_count, char* args_sizes) */
/* Instructions to enter a compartment. There is no `ret`, as we need to
 * perform a context switch upon exiting, which is done via `ldpbr`
 */
.global comp_exec_in
.type comp_exec_in, "function"
comp_exec_in:
    stp lr, x29, [sp, #-16]!
    mov x19, sp

    // Move arguments to temporary registers (we'll need them later)
    mov x9, x0
    mov c10, c1
    mov x11, x2

    // Load params (only handle 3 params):
loading_params:
    cbz  x4, loaded_params
    ldrb w6, [x5], #1 // Get size of argument to load in `x6`
                      // Increment `x5` by 1 byte since it's `char`s
    bl   load_param_by_size
    mov  x0, x8       // Store one argument
    add  x3, x3, x6   // Shift array pointer by size of argument
    sub  x4, x4, #1

    cbz  x4, loaded_params
    ldrb w6, [x5], #1
    bl   load_param_by_size
    mov  x1, x8
    add  x3, x3, x6
    sub  x4, x4, #1

    cbz  x4, loaded_params
    ldrb w6, [x5], #1
    bl   load_param_by_size
    mov  x2, x8
    add  x3, x3, x6
    sub  x4, x4, #1
    b    loaded_params

load_param_by_size:
    neg  x7, x6, lsl #3 // Get number of bits to throw away (0 - x6 * 8)
    ldr  x8, [x3]       // Load next 64 bits of argument
    lsl  x8, x8, x7     // Shift left to remove unneeded upper bits,
                        // shifting in 0s on the right
    lsr  x8, x8, x7     // Shift back right, again shifting in 0s on the left
    ret

loaded_params:
    // Clean
    mov x3, xzr
    mov x4, xzr
    mov x5, xzr
    mov x6, xzr
    mov x7, xzr
    mov x8, xzr

    mov sp, x9
    msr DDC, c10
    blr x11

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
