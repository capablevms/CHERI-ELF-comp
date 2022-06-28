.text
.balign 4
.global intercept_wrapper
.type intercept_wrapper, "function"
// TODO restore c29
intercept_wrapper:
    mrs c28, ddc
    msr ddc, c29
    stp clr, c28, [sp, #-32]!
    blr x10
    ldp clr, c28, [sp], #32
    msr ddc, c28
    mov x29, #0
    ret

.global compartment_transition_out
.type compartment_transition_out, "function"
compartment_transition_out:
    stp c29, clr, [sp, #-32]!
    ldpblr c29, [c11] // TODO save c11?
    ldp c29, clr, [sp], #32
    ret
compartment_transition_out_end:

/* comp_exec_in(void* comp_sp, void* __capability comp_ddc, void* fn) */
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

// Expect DDC in c29, reset `sp` and `clr`
// result should be in `x0`
.global comp_exec_out
.type comp_exec_out, "function"
comp_exec_out:
    msr DDC, c29
    mov sp, x19
    ldp lr, x29, [sp], #16
    ret
