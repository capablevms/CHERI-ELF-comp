#include "compartment.h"

static size_t comps_id = 0;
struct Compartment** comps;

struct Compartment*
comp_init()
{
    // TODO order
    struct Compartment* new_comp = (struct Compartment*) malloc(sizeof(struct Compartment));
    new_comp->id = comps_id++;

    new_comp->phdr = 0;
    new_comp->ddc = NULL;

    new_comp->size = 0;
    new_comp->base = 0;
    new_comp->entry_point = 0;
    new_comp->relas_cnt = 0;
    new_comp->mapped = false;
    new_comp->mapped_full = false;

    new_comp->seg_count = 0;
    new_comp->segs_size = 0;

    new_comp->alloc_head = NULL;
    new_comp->page_size = sysconf(_SC_PAGESIZE);
    new_comp->curr_intercept_count = 0;

    return new_comp;
}


/*******************************************************************************
 * Main compartment functions
 ******************************************************************************/

struct Compartment*
comp_from_elf(char* filename)
{
    struct Compartment* new_comp = comp_init();
    int pread_res;

    // Read elf headers
    Elf64_Ehdr comp_ehdr;
    new_comp->fd = open(filename, O_RDONLY);
    assert(new_comp->fd != -1);
    pread_res = pread(new_comp->fd, &comp_ehdr, sizeof(comp_ehdr), 0);
    assert(pread_res != -1);
    new_comp->elf_type = comp_ehdr.e_type;
    assert(new_comp->elf_type == ET_DYN || new_comp->elf_type == ET_EXEC);

    const unsigned long new_comp_base = 0x1000000UL; // TODO
    assert(new_comp_base % new_comp->page_size == 0);
    new_comp->base = new_comp_base;

    struct stat elf_fd_stat;
    fstat(new_comp->fd, &elf_fd_stat);
    new_comp->size = elf_fd_stat.st_size;
    /*new_comp->entry_point = new_comp_base + comp_ehdr.e_entry;*/
    new_comp->phentsize = comp_ehdr.e_phentsize;
    new_comp->phnum = comp_ehdr.e_phnum;

    // Read program headers
    Elf64_Phdr comp_phdr;
    size_t align_size_correction;
    for (size_t i = 0; i < comp_ehdr.e_phnum; ++i)
    {
        pread_res = pread((int) new_comp->fd, &comp_phdr, sizeof(comp_phdr),
                comp_ehdr.e_phoff + i * sizeof(comp_phdr));
        assert(pread_res != -1);

        /*if (comp_phdr.p_offset <= comp_ehdr.e_phoff &&*/
                /*(comp_ehdr.e_phoff + comp_ehdr.e_phnum * comp_ehdr.e_phentsize)*/
                    /*<= comp_phdr.p_offset + comp_phdr.p_filesz)*/
        /*{*/
            /*new_comp->phdr = 0; // TODO?*/
            /*continue;*/
        /*}*/

        if (comp_phdr.p_type != PT_LOAD)
        {
            continue;
        }

        struct SegmentMap* this_seg =
            (struct SegmentMap*) malloc(sizeof(struct SegmentMap));
        assert(this_seg != NULL);
        if (new_comp->elf_type == ET_DYN /*|| new_comp->elf_type == ET_EXEC*/) // TODO distinguish PIE exec vs non-PIE exec
        {
            unsigned long curr_seg_base = new_comp_base + comp_phdr.p_vaddr;
            this_seg->mem_bot = align_down(curr_seg_base, new_comp->page_size);
            align_size_correction = curr_seg_base - this_seg->mem_bot;
            this_seg->mem_top = curr_seg_base + comp_phdr.p_memsz;
        }
        else if (new_comp->elf_type == ET_EXEC)
        {
            this_seg->mem_bot = align_down(comp_phdr.p_vaddr, new_comp->page_size);
            align_size_correction = comp_phdr.p_vaddr - this_seg->mem_bot;
            this_seg->mem_top = comp_phdr.p_vaddr + comp_phdr.p_memsz;
        }
        else
        {
            assert(false && "Unhandled elf type"); // TODO move elsewhere
        }
        this_seg->offset = align_down(comp_phdr.p_offset, new_comp->page_size);
        /*this_seg->size = comp_phdr.p_filesz + (comp_phdr.p_offset & (new_comp->page_size - 1)); // TODO ????*/
        this_seg->mem_sz = comp_phdr.p_memsz + align_size_correction;
        this_seg->file_sz = comp_phdr.p_filesz + align_size_correction;
        this_seg->correction = align_size_correction;
        this_seg->prot_flags = (comp_phdr.p_flags & PF_R ? PROT_READ : 0) |
                                (comp_phdr.p_flags & PF_W ? PROT_WRITE : 0) |
                                (comp_phdr.p_flags & PF_X ? PROT_EXEC : 0);
        printf("Added segment for header %lu:\n", i);
        segmap_print(this_seg);

        new_comp->segs[new_comp->seg_count] = this_seg;
        new_comp->seg_count += 1;
        new_comp->segs_size += this_seg->mem_sz;
    }

    // Define scratch memory available
    new_comp->scratch_mem_base = align_up(new_comp->segs[new_comp->seg_count - 1]->mem_top + new_comp->page_size, new_comp->page_size);
    new_comp->scratch_mem_size = 0x40000UL;
    new_comp->scratch_mem_alloc = 0;
    new_comp->scratch_mem_stack_top = align_down(new_comp->scratch_mem_base + new_comp->scratch_mem_size, 16);
    new_comp->scratch_mem_stack_size = 0x8000UL;
    assert(new_comp->scratch_mem_base % 16 == 0);
    assert((new_comp->scratch_mem_base + new_comp->scratch_mem_size) % 16 == 0);
    assert(new_comp->scratch_mem_stack_top % 16 == 0);
    assert((new_comp->scratch_mem_stack_top - new_comp->scratch_mem_stack_size) % 16 == 0);

    Elf64_Shdr comp_symtb_hdr; // TODO change name
    size_t found = 0;
    const size_t to_find = 1 + MAX_INTERCEPT_COUNT;
    for (size_t i = 0; i < comp_ehdr.e_shnum; ++i)
    {
        pread_res = pread((int) new_comp->fd, &comp_symtb_hdr, sizeof(Elf64_Shdr),
                comp_ehdr.e_shoff + i * sizeof(Elf64_Shdr));
        assert(pread_res != -1);

        // Find functions of interest in injected ELF file
        if (comp_symtb_hdr.sh_type == SHT_SYMTAB)
        {
            assert(!found);
            Elf64_Shdr comp_strtb_hdr;
            pread_res = pread((int) new_comp->fd, &comp_strtb_hdr, sizeof(Elf64_Shdr), comp_ehdr.e_shoff + comp_symtb_hdr.sh_link * sizeof(Elf64_Shdr));
            assert(pread_res != -1);
            char* comp_strtb = (char*) malloc(comp_strtb_hdr.sh_size);
            pread_res = pread((int) new_comp->fd, comp_strtb, comp_strtb_hdr.sh_size, comp_strtb_hdr.sh_offset);
            assert(pread_res != -1);

            Elf64_Sym* comp_symtb = (Elf64_Sym*) malloc(comp_symtb_hdr.sh_size);
            pread_res = pread((int) new_comp->fd, comp_symtb, comp_symtb_hdr.sh_size, comp_symtb_hdr.sh_offset);
            assert(pread_res != -1);

            size_t syms_count = comp_symtb_hdr.sh_size / sizeof(Elf64_Sym);
            Elf64_Sym curr_sym;
            for (size_t j = 0; j < syms_count; ++j)
            {
                curr_sym = comp_symtb[j];
                if (!strcmp("main", &comp_strtb[curr_sym.st_name])) // TODO entry point name
                {
                    switch(new_comp->elf_type)
                    {
                        case ET_DYN:
                        {
                            new_comp->entry_point = new_comp->base + curr_sym.st_value;
                            break;
                        }
                        case ET_EXEC:
                        {
                            new_comp->entry_point = curr_sym.st_value;
                            break;
                        }
                        default:
                            assert(false);
                    }
                    found += 1;
                    printf("Found `main` func at %p.\n", (void*) new_comp->entry_point);
                }
                else
                {
                    for (size_t i = 0; i < MAX_INTERCEPT_COUNT; ++i)
                    {
                        if (!strcmp(comp_intercept_funcs[i].func_name, &comp_strtb[curr_sym.st_name]))
                        {
                            comp_add_intercept(new_comp, curr_sym.st_value, comp_intercept_funcs[i]);
                            found += 1;
                            break;
                        }
                    }
                }
                if (found == to_find)
                {
                    break;
                }
            }
            free(comp_symtb);
            free(comp_strtb);
        }
        // TODO still need relas check or consider only static executables?
        else if (comp_symtb_hdr.sh_type == SHT_RELA) // TODO change name && consider SH_REL
        {
            if (comp_symtb_hdr.sh_info == 0) // TODO better identify the plt relocation section
            {
                continue;
            }

            new_comp->relas_cnt = comp_symtb_hdr.sh_size / sizeof(Elf64_Rela);
            new_comp->relas = (uintptr_t*) malloc(new_comp->relas_cnt * sizeof(uintptr_t));
            Elf64_Rela* comp_relas = (Elf64_Rela*) malloc(comp_symtb_hdr.sh_size);
            pread_res = pread((int) new_comp->fd, comp_relas, comp_symtb_hdr.sh_size, comp_symtb_hdr.sh_offset);
            assert(pread_res != -1);

            for (size_t j = 0; j < new_comp->relas_cnt; ++j)
            {
                new_comp->relas[j] = comp_relas[j].r_offset;
                /*comp_relas[j].r_offset += new_comp->base;*/
                /*uintptr_t old_plt_val = (uintptr_t) *((void**) comp_relas[j].r_offset);*/
                /*old_plt_val += new_comp->base;*/
            }

            free(comp_relas);
        }
        else
        {
            continue;
        }
    }
    /*assert(found == to_find);*/

    comp_register_ddc(new_comp);
    comp_print(new_comp);
    return new_comp;
}

void
comp_register_ddc(struct Compartment* new_comp)
{
    void* __capability new_ddc = cheri_address_set(manager_ddc, new_comp->base);
    new_ddc = cheri_bounds_set(new_ddc, new_comp->size + new_comp->scratch_mem_size + new_comp->scratch_mem_stack_size);
    // TODO bounds double-check
    new_comp->ddc = new_ddc;
}

void
comp_add_intercept(struct Compartment* new_comp, uintptr_t intercept_target, struct func_intercept intercept_data)
{
    printf("Found `%s` func at %p.\n", intercept_data.func_name, (void*) intercept_target);
    int offset = (intercept_data.redirect_func - intercept_target) / 4;
    assert(offset < (1 << 27));
    offset &= (1 << 26) - 1;
    const int arm_b_instr_mask = 0b101 << 26;
    uint32_t instr_binary = arm_b_instr_mask | offset;
    int* init_addr_ptr = (void*) intercept_target;
    struct intercept_patch new_patch = { init_addr_ptr, instr_binary };
    new_comp->patches[new_comp->curr_intercept_count] = new_patch;
    new_comp->curr_intercept_count += 1;
}

void
comp_stack_push(struct Compartment* comp, const void* to_push, size_t to_push_sz)
{
    comp->stack_pointer -= to_push_sz;
    memcpy((void*) comp->stack_pointer, to_push, to_push_sz);
    assert(comp->stack_pointer > comp->scratch_mem_stack_top - comp->scratch_mem_stack_size);
}

void
comp_stack_auxval_push(struct Compartment* comp, uint64_t at_type, uint64_t at_val)
{
    Elf64_Auxinfo new_auxv = {at_type, {at_val} };
    comp_stack_push(comp, &new_auxv, sizeof(new_auxv));
}

void
comp_map(struct Compartment* to_map)
{
    assert(!(to_map->mapped || to_map->mapped_full));
    struct SegmentMap* curr_seg;
    void* map_result;

    for (size_t i = 0; i < to_map->seg_count; ++i)
    {
        curr_seg = to_map->segs[i];
        printf("Currently mapping segment %lu:\n", i);
        segmap_print(curr_seg);
        if (curr_seg->file_sz == curr_seg->mem_sz)
        {
            map_result = mmap((void*) curr_seg->mem_bot,
                                    curr_seg->file_sz,
                                    /*curr_seg->prot_flags,*/ // TODO currently need read/write to inject the intercepts, consider better option
                                    PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_FIXED,
                                    to_map->fd, curr_seg->offset);
        }
        else
        {
            assert(curr_seg->mem_sz > curr_seg->file_sz);
            map_result = mmap((void*) curr_seg->mem_bot,
                                    curr_seg->mem_sz,
                                    curr_seg->prot_flags,
                                    MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                                    -1, 0);
            assert(map_result !=  MAP_FAILED);
            int pread_res = pread(to_map->fd, (void*) curr_seg->mem_bot,
                                  curr_seg->file_sz, curr_seg->offset);
            assert(pread_res != -1);
        }
    }

    printf("Currently mapping compartment scratch memory + stack\n");
    map_result = mmap((void*) to_map->scratch_mem_base,
                      to_map->scratch_mem_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                      -1, 0);
    assert(map_result != MAP_FAILED);
    map_result = mmap((void*) to_map->scratch_mem_stack_top - to_map->scratch_mem_stack_size,
                      to_map->scratch_mem_stack_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_STACK,
                      -1, 0);
    to_map->stack_pointer = to_map->scratch_mem_stack_top;
    assert(map_result != MAP_FAILED);

    for (size_t i = 0; i < to_map->relas_cnt; ++i)
    {
        uintptr_t rela_addr = to_map->relas[i] + to_map->base;
        uintptr_t old_plt_val = (uintptr_t) *((void**) rela_addr);
        old_plt_val += to_map->base;
        *((uintptr_t *) rela_addr) = old_plt_val;
    }

    for (size_t i = 0; i < to_map->curr_intercept_count; ++i)
    {
        struct intercept_patch to_patch = to_map->patches[i];
        *to_patch.patch_addr = to_patch.instr;
    }

    to_map->mapped = true;
}

void ddc_set(void *__capability cap) {
    assert(cap != NULL);
    asm volatile("MSR DDC, %[cap]" : : [cap] "C"(cap) : "memory");
}

int64_t
comp_exec(struct Compartment* to_exec)
{
    void* fn = (void*) to_exec->entry_point;
    void* wrap_sp;

    /*setup_stack(to_exec);*/

    int64_t result;

/*#if __has_feature(capabilities)*/
    /*ddc_set(to_exec->ddc);*/
/*#endif*/

    // TODO handle register clobbering stuff (`syscall-restrict` example)
    // https://github.com/capablevms/cheri_compartments/blob/master/code/signal_break.c#L46
    // TODO save sp/lr on the compartment stack, and ensure they can't be misused somehow
    asm("str lr, [sp, #-16]!\n\t"
        "mov sp, %[comp_sp]\n\t"
        "ldr c0, %[comp_ddc]\n\t"
        "msr DDC, c0\n\t"
        "blr %[fn]\n\t"
        "ldr c1, %[manager_ddc]\n\t"
        "msr DDC, c1\n\t" // TODO should fail
        "ldr x1, %[wrap_sp]\n\t"
        "mov sp, x1\n\t"
        "ldr lr, [sp], #16\n\t"
        "mov %[result], x0"
         : [wrap_sp]"+m"(wrap_sp), [result]"+r"(result)
         : [fn]"r"(fn), [comp_sp]"r"(to_exec->stack_pointer),
           [manager_ddc]"m"(manager_ddc), [comp_ddc]"m"(to_exec->ddc)
         : "memory");
/*#if __has_feature(capabilities)*/
    /*ddc_set(manager_ddc);*/
/*#endif*/
    // TODO reset SP
    return result;
}

void
comp_clean(struct Compartment* to_clean)
{
    close(to_clean->fd);
    if (to_clean->mapped)
    {
        for (size_t i = 0; i < to_clean->seg_count; ++i)
        {
            free(to_clean->segs[i]);
            // TODO unmap
        }
    }
    else if (to_clean->mapped_full)
    {
        // TODO unmap
    }
    free(to_clean);
    // TODO
}

void
log_new_comp(struct Compartment* to_log)
{
    comps = realloc(comps, sizeof(comps) + sizeof(struct Compartment));
    comps[to_log->id] = to_log;
}

struct Compartment*
find_comp_by_addr(void* to_find)
{
    assert(comps[0]->base <= (uintptr_t) to_find);
    assert(comps[0]->base + comps[0]->size > (uintptr_t) to_find);
    return comps[0]; // TODO
}

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

// TODO WIP
void
setup_stack(struct Compartment* to_setup)
{
    assert(to_setup->stack_pointer % 16 == 0);

    uintptr_t init_sp = to_setup->stack_pointer;
    uintptr_t argv_ptrs[to_setup->argc];
    for (size_t i = 0; i < to_setup->argc; ++i)
    {
        comp_stack_push(to_setup, to_setup->argv[i], strlen(to_setup->argv[i]));
        argv_ptrs[i] = to_setup->stack_pointer;
    }

    uintptr_t envp_ptrs[ENV_FIELDS_CNT];
    const char* envp_val;
    for (size_t i = 0; i < ENV_FIELDS_CNT; ++i)
    {
        envp_val = get_env_str(comp_env_fields[i]);
        comp_stack_push(to_setup, envp_val, strlen(envp_val));
        envp_ptrs[i] = to_setup->stack_pointer;
    }

    size_t stack_push_size = (1 + 1 + 1 + sizeof(envp_ptrs) + sizeof(argv_ptrs)) * sizeof(uint64_t);
    void* null_delim = NULL;
    /* argc */
    size_t stack_argc = to_setup->argc;
    comp_stack_push(to_setup, &stack_argc, sizeof(uint64_t));
    /* argv */
    for (size_t i = 0; i < to_setup->argc; ++i)
    {
        comp_stack_push(to_setup, (void*) &argv_ptrs[i], sizeof(uint64_t));
    }
    /* argv NULL delimiter */
    comp_stack_push(to_setup, &null_delim, sizeof(null_delim));
    /* envp */
    for (size_t i = 0; i < ENV_FIELDS_CNT; ++i) // envp
    {
        /*comp_stack_push(comp_envs[i], strlen(comp_envs[1] + 1);*/
        comp_stack_push(to_setup, (void*) &envp_ptrs[i], sizeof(uint64_t));
    }
    /* envp NULL delimiter */
    comp_stack_push(to_setup, &null_delim, sizeof(null_delim));
    /* auxv */
    comp_stack_auxval_push(to_setup, AT_PAGESZ, elf_aux_info(AT_PAGESZ, NULL, sizeof(size_t)));
    comp_stack_auxval_push(to_setup, AT_PHDR, to_setup->phdr);
    comp_stack_auxval_push(to_setup, AT_PHENT, to_setup->phentsize);
    comp_stack_auxval_push(to_setup, AT_PHNUM, to_setup->phnum);
    /*comp_stack_auxval_push(to_setup, AT_SECURE, 0);*/
    /*comp_stack_auxval_push(to_setup, AT_RANDOM, rand());*/
    comp_stack_auxval_push(to_setup, AT_NULL, 0);

    to_setup->stack_pointer = init_sp;

}

/*******************************************************************************
 * Print functions
 * TODO complete these once structs stabilize
 ******************************************************************************/

void
comp_print(struct Compartment* to_print)
{
    printf("=== COMPARTMENT ===\n");
    printf("\t * ID      --- %lu\n", to_print->id);
    printf("\t * FD      --- %d\n", to_print->fd);
    printf("\t * SIZE    --- %lu\n", to_print->size);
    printf("\t * BASE    --- %#010x\n", (unsigned int) to_print->base);
    printf("\t * ENTRY   --- %#010x\n", (unsigned int) to_print->entry_point);
    printf("\t * RELACNT --- %lu\n", to_print->relas_cnt);
    printf("\t * MAPD    --- %d\n", to_print->mapped);
    printf("\t * MAPDF   --- %d\n", to_print->mapped_full);
    printf("\t * SEGC    --- %lu\n", to_print->seg_count);
    printf("\t * SEGS    --- ");
    for (size_t i = 0; i < to_print->seg_count; ++i)
    {
        printf("%p, ", to_print->segs[i]);
    }
    printf("\n");
    printf("\t * SEGSZ   --- %lu\n", to_print->segs_size);
    printf("\t * PGSZ    --- %lu\n", to_print->page_size);
}

void
segmap_print(struct SegmentMap* to_print)
{
    printf("=== SEGMENT MAP ===\n");
    printf("\t * BOT  --- %#010x\n", (unsigned int) to_print->mem_bot);
    printf("\t * TOP  --- %#010x\n", (unsigned int) to_print->mem_top);
    printf("\t * OFF  --- %zu\n", to_print->offset);
    printf("\t * M_SZ --- %zu\n", to_print->mem_sz);
    printf("\t * F_SZ --- %zu\n", to_print->file_sz);
    printf("\t * CORR --- %zu\n", to_print->correction);
    printf("\t * FLAG --- %d\n", to_print->prot_flags);
}
