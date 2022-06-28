#ifndef _COMPARTMENT_H
#define _COMPARTMENT_H

#include <assert.h>
#include <elf.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cheriintrin.h"

#include "manager.h"

#define align_down(x, align)    __builtin_align_down(x, align)
#define align_up(x, align)      __builtin_align_up(x, align)

// Maximum number of allowed segments per loaded ELF file
// TODO rethink number/make it a parameter
#define SEG_MAX_COUNT 20

// TODO once things stabilize, recheck if all struct members are required
// currently there's quite a bit of redundancy to make things easier to think
// about

struct func_intercept;
void compartment_transition_out();
int64_t comp_exec_in(void*, void* __capability, void*);
void comp_exec_out();

#define INTERCEPT_INSTR_COUNT 5
#define COMP_TRANS_FN_INSTR_CNT 4

struct intercept_patch
{
    int* patch_addr;
    int32_t instr[INTERCEPT_INSTR_COUNT];
    uintptr_t comp_manager_cap_addr;
    void* __capability manager_cap;
};

/* Struct representing one segment of an ELF binary.
 *
 * TODO expand */
struct SegmentMap
{
    uintptr_t mem_bot;
    uintptr_t mem_top;
    size_t offset;
    size_t correction;
    size_t mem_sz;
    size_t file_sz;
    int prot_flags;
};

struct Compartment
{
    // Identifiers
    size_t id;
    int fd;
    Elf64_Half elf_type;
    // Execution info
    size_t argc;
    char** argv;
    Elf64_Half phdr;
    Elf64_Half phentsize;
    Elf64_Half phnum;
    void* __capability ddc;
    // ELF data
    size_t size;
    uintptr_t base;
    uintptr_t entry_point;
    uintptr_t* relas;
    size_t relas_cnt;
    bool mapped;
    bool mapped_full;
    // Segments data
    struct SegmentMap* segs[SEG_MAX_COUNT]; // TODO
    size_t seg_count;
    size_t segs_size;
    // Scratch memory
    uintptr_t scratch_mem_base;
    size_t scratch_mem_size;
    size_t scratch_mem_alloc;

    size_t scratch_mem_heap_size;
    uintptr_t scratch_mem_stack_top;
    size_t scratch_mem_stack_size;
    uintptr_t stack_pointer;
    struct mem_alloc* alloc_head;

    uintptr_t manager_caps;
    size_t max_manager_caps_count;
    size_t active_manager_caps_count;

    uintptr_t mng_trans_fn;
    size_t mng_trans_fn_sz;
    // Hardware info - maybe move
    size_t page_size;
    // Misc
    short curr_intercept_count;
    struct intercept_patch patches[MAX_INTERCEPT_COUNT];

};

extern struct Compartment** comps;

struct Compartment* comp_init();
struct Compartment* comp_from_elf(char*);
void comp_register_ddc(struct Compartment*);
void comp_add_intercept(struct Compartment*, uintptr_t, struct func_intercept);
void comp_stack_push(struct Compartment*, const void*, size_t);
void comp_map(struct Compartment*);
void comp_map_full(struct Compartment*);
int64_t comp_exec(struct Compartment*);
void comp_clean(struct Compartment*);

void log_new_comp(struct Compartment*);
struct Compartment* find_comp(struct Compartment*);

void setup_stack(struct Compartment*);

void comp_print(struct Compartment*);
void segmap_print(struct SegmentMap*);

#endif // _COMPARTMENT_H
