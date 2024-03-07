#ifndef _COMPARTMENT_H
#define _COMPARTMENT_H

#include <assert.h>
#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cheriintrin.h"

// Morello `gcc` defines `ptraddr_t` in `stddef.h`, while `clang` does so in
// `stdint.h`
// TODO are there any other diverging definition files?
#if defined(__GNUC__) && !defined(__clang__)
#include <stddef.h>
#endif

#define align_down(x, align) __builtin_align_down(x, align)
#define align_up(x, align) __builtin_align_up(x, align)

// TODO once things stabilize, recheck if all struct members are required
// currently there's quite a bit of redundancy to make things easier to think
// about

void
compartment_transition_out();
int64_t
comp_exec_in(
    void *, void *__capability, void *, void *, size_t, void *__capability);
void
comp_exec_out();

// Declare built-in function for cache synchronization:
// https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/caches-and-self-modifying-code
extern void
__clear_cache(void *, void *);

// Number of instructions to inject at intercepted function call point
// TODO ensure there is sufficient space for these, so we don't spill over
#define INTERCEPT_INSTR_COUNT 5

// Number of instructions required by the transition function
#define COMP_TRANS_FN_INSTR_CNT 4

extern void *__capability sealed_redirect_cap;
extern void *__capability comp_return_caps[2];

/* For a function to be intercepted, information required to insert the
 * redirect code and perform redirection
 *
 * TODO recheck this is properly used, or re-design into a more light-weight
 * approach with pre-given transition capabilities
 */
struct InterceptPatch
{
    int *patch_addr;
    int32_t instr[INTERCEPT_INSTR_COUNT];
    uintptr_t comp_manager_cap_addr;
    void *__capability manager_cap;
};

// Maximum size of an argument, in bytes
#define COMP_ARG_SIZE 8

// This is a guard for the expected size of an argument, and a consequence of
// using `x` registers in `loading_params` in `transition.S`. This should be
// the equivalent of checking for a 64-bit CHERI aware platform
// TODO is there a better way to check?
#if !(__LP64__ && defined(__CHERI__))
#error Expecting 64-bit Arm Morello platform
#endif

/* Struct representing a valid entry point to a compartment
 */
struct CompEntryPoint
{
    const char *fn_name;
    void *fn_addr;
};

/* Struct representing one segment of an ELF binary.
 *
 * TODO expand */
struct SegmentMap
{
    void *mem_bot;
    void *mem_top;
    size_t offset;
    ptrdiff_t correction;
    size_t mem_sz;
    size_t file_sz;
    int prot_flags;
};

/* Struct representing an eager relocation to be made at map-time - instead of
 * lazily looking up function addresses once a function is called at runtime,
 * via PLT/GOT, we update the expected addresses eagerly once the code is
 * mapped into memory, via `comp_map`
 */
struct LibRelaMapping
{
    char *rela_name;
    void *rela_address; // address of relocation in compartment
    void *target_func_address; // address of actual function
    unsigned short rela_type;
};

/* Struct representing a symbol entry of a dependency library
 */
struct LibDependencySymbol
{
    char *sym_name;
    void *sym_offset;
    unsigned short sym_type;
};

/* Struct representing the result of searching for a library symbol in a
 * compartment
 */
struct LibSymSearchResult
{
    unsigned short lib_idx;
    unsigned short sym_idx;
};

/**
 * Struct representing a library dependency for one of our given compartments
 */
struct LibDependency
{
    char *lib_name;
    char *lib_path;
    void *lib_mem_base;

    // Segments of interest (usually, of type `PT_LOAD`) within this library
    size_t lib_segs_count;
    size_t lib_segs_size;
    struct SegmentMap *lib_segs;

    // Symbols within this library
    size_t lib_syms_count;
    struct LibDependencySymbol *lib_syms;

    // Library dependencies for this library
    unsigned short lib_dep_count;
    char **lib_dep_names;

    // Symbols within this library that need eager relocation
    size_t rela_maps_count;
    struct LibRelaMapping *rela_maps;
};

/**
 * Struct representing ELF data necessary to load and eventually execute a
 * compartment
 */
struct Compartment
{
    // Identifiers
    size_t id;
    // Execution info
    void *__capability ddc;
    // ELF data
    size_t size; // size of compartment in memory
    void *base; // address where to load compartment
    void *mem_top;
    bool mapped;

    // Scratch memory
    void *scratch_mem_base;
    size_t scratch_mem_size;
    size_t scratch_mem_alloc;

    size_t scratch_mem_heap_size;
    void *scratch_mem_stack_top;
    size_t scratch_mem_stack_size;
    void *stack_pointer;
    struct MemAlloc *alloc_head;

    // TODO double check / rework this process
    void *manager_caps;
    size_t max_manager_caps_count;
    size_t active_manager_caps_count;

    // Transition function (duplicated across compartments, but must be within
    // to be within DDC bounds)
    void *mng_trans_fn;
    size_t mng_trans_fn_sz;

    // Internal libraries and relocations
    size_t libs_count;
    struct LibDependency **libs;
    size_t entry_point_count;
    struct CompEntryPoint *entry_points;

    // Hardware info - maybe move
    size_t page_size;

    // Misc
    unsigned short curr_intercept_count;
    struct InterceptPatch *intercept_patches;
};

int
entry_point_cmp(const void *, const void *);
struct Compartment *
comp_init();
struct Compartment *
comp_from_elf(char *, char **, size_t, char **, void **, size_t, void *);
void
comp_add_intercept(struct Compartment *, uintptr_t, uintptr_t);
void
comp_map(struct Compartment *);
void
comp_map_full(struct Compartment *);
int64_t
comp_exec(struct Compartment *, char *, void *, size_t);
void
comp_clean(struct Compartment *);

struct Compartment *
find_comp(struct Compartment *);

#endif // _COMPARTMENT_H
