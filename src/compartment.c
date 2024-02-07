#include "compartment.h"

/* Initialize some values of the Compartment struct. The rest are expected to
 * be set in `comp_from_elf`.
 */
struct Compartment*
comp_init()
{
    // TODO order
    struct Compartment* new_comp =
        (struct Compartment*) malloc(sizeof(struct Compartment));

    new_comp->phdr = 0;
    new_comp->ddc = NULL;

    new_comp->size = 0;
    new_comp->base = 0;
    new_comp->entry_point_count = 0;
    new_comp->mapped = false;
    new_comp->mapped_full = false;

    new_comp->seg_count = 0;
    new_comp->segs_size = 0;
    new_comp->mng_trans_fn_sz = sizeof(uint32_t) * COMP_TRANS_FN_INSTR_CNT; // TODO ptr arithmetic
    new_comp->phdr = 0;
    new_comp->alloc_head = NULL;

    new_comp->rela_maps_count = 0;

    new_comp->page_size = sysconf(_SC_PAGESIZE);
    new_comp->curr_intercept_count = 0;

    return new_comp;
}

/*******************************************************************************
 * Main compartment functions
 ******************************************************************************/

/* Comparison function for `struct entry_point`
 */
int
entry_point_cmp(const void* val1, const void* val2)
{
    struct entry_point* ep1 = *(struct entry_point**) val1;
    struct entry_point* ep2 = *(struct entry_point**) val2;
    return strcmp(ep1->fn_name, ep2->fn_name);
}

/* Give a binary ELF file in `filename`, read the ELF data and store it within
 * a `struct Compartment`. At this point, we only read data.
 */
struct Compartment*
comp_from_elf(char* filename,
              char** entry_points, size_t entry_point_count,
              char** intercepts, void** intercept_addrs, size_t intercept_count,
              void* new_comp_base)
{
    struct Compartment* new_comp = comp_init();

    new_comp->fd = open(filename, O_RDONLY);
    if (new_comp->fd == -1)
    {
        free(new_comp);
        errx(1, "Error opening compartment file  %s!\n", filename);
    }

    assert(entry_points);
    assert(entry_point_count > 0);
    new_comp->comp_fns = malloc(entry_point_count * sizeof(struct entry_point));

    // Read elf headers
    Elf64_Ehdr comp_ehdr;
    assert(new_comp->fd != -1);
    do_pread(new_comp->fd, &comp_ehdr, sizeof(Elf64_Ehdr), 0);
    new_comp->elf_type = comp_ehdr.e_type;
    assert(new_comp->elf_type == ET_DYN || new_comp->elf_type == ET_EXEC);

    struct stat elf_fd_stat;
    fstat(new_comp->fd, &elf_fd_stat);
    // TODO re-check these
    new_comp->size = elf_fd_stat.st_size;

    // Read program headers
    Elf64_Phdr comp_phdr;
    ptrdiff_t align_size_correction;
    bool first_load_header = true;
    for (size_t i = 0; i < comp_ehdr.e_phnum; ++i)
    {
        do_pread((int) new_comp->fd, &comp_phdr, sizeof(comp_phdr),
                 comp_ehdr.e_phoff + i * sizeof(comp_phdr));

        // We only need to keep `PT_LOAD` segments, so we can map them later
        if (comp_phdr.p_type != PT_LOAD)
        {
            continue;
        }

        if (new_comp->elf_type == ET_DYN)
        {
            new_comp->base = new_comp_base;
        }
        // Compute loading address of compartment for static binary
        // TODO empirically, the first `LOAD` program header seems to expect to be
        // loaded at the lowest address; is this correct?
        else if (first_load_header)
        {
            void* new_comp_base = (void*) comp_phdr.p_vaddr;
            assert((uintptr_t) new_comp_base % new_comp->page_size == 0);
            new_comp->base = new_comp_base;
            first_load_header = false;
        }

        // Setup mapping info for the current segment
        struct SegmentMap* this_seg =
            (struct SegmentMap*) malloc(sizeof(struct SegmentMap));
        assert(this_seg != NULL);
        if (new_comp->elf_type == ET_DYN /*|| new_comp->elf_type == ET_EXEC*/) // TODO distinguish PIE exec vs non-PIE exec
        {
            void* curr_seg_base = (char*) new_comp->base + comp_phdr.p_vaddr;
            this_seg->mem_bot = align_down(curr_seg_base, new_comp->page_size);
            align_size_correction = (char*) curr_seg_base - (char*) this_seg->mem_bot;
            this_seg->mem_top = (char*) curr_seg_base + comp_phdr.p_memsz;
        }
        else if (new_comp->elf_type == ET_EXEC)
        {
            // TODO maybe just remove this if if we don't want to support
            // static binaries anymore
            assert(false);
            this_seg->mem_bot =
                align_down((void*) comp_phdr.p_vaddr, new_comp->page_size);
            align_size_correction =
                (char*) comp_phdr.p_vaddr - (char*) this_seg->mem_bot;
            this_seg->mem_top = (char*) comp_phdr.p_vaddr + comp_phdr.p_memsz;
        }
        else
        {
            errx(1, "Unhandled ELF type");
        }
        this_seg->offset = align_down(comp_phdr.p_offset, new_comp->page_size);
        this_seg->mem_sz = comp_phdr.p_memsz + align_size_correction;
        this_seg->file_sz = comp_phdr.p_filesz + align_size_correction;
        this_seg->correction = align_size_correction;
        this_seg->prot_flags = (comp_phdr.p_flags & PF_R ? PROT_READ : 0) |
                                (comp_phdr.p_flags & PF_W ? PROT_WRITE : 0) |
                                (comp_phdr.p_flags & PF_X ? PROT_EXEC : 0);

        new_comp->segs =
            realloc(new_comp->segs,
                    (new_comp->seg_count + 1) * sizeof(struct SegmentMap*));
        new_comp->segs[new_comp->seg_count] = this_seg;
        new_comp->seg_count += 1;
        new_comp->segs_size += align_up(this_seg->mem_sz, comp_phdr.p_align);
    }

    // Load `.shstr` section, so we can check section names
    Elf64_Shdr comp_sh_strtb_hdr;
    do_pread((int) new_comp->fd, &comp_sh_strtb_hdr, sizeof(Elf64_Shdr),
             comp_ehdr.e_shoff + comp_ehdr.e_shstrndx * sizeof(Elf64_Shdr));
    char* comp_sh_strtb = malloc(comp_sh_strtb_hdr.sh_size);
    do_pread((int) new_comp->fd, comp_sh_strtb, comp_sh_strtb_hdr.sh_size,
             comp_sh_strtb_hdr.sh_offset);

    init_comp_scratch_mem(new_comp);
    new_comp->mem_top = new_comp->scratch_mem_stack_top;

    // Find indices of interest that we'll use later
    const size_t headers_of_interest_count = 3;
    size_t found_headers = 0;
    Elf64_Shdr comp_symtb_shdr;
    Elf64_Shdr comp_rela_plt_shdr;
    Elf64_Shdr comp_dynamic_shdr;
    Elf64_Shdr curr_shdr;
    for (size_t i = 0; i < comp_ehdr.e_shnum; ++i)
    {
        do_pread((int) new_comp->fd, &curr_shdr, sizeof(Elf64_Shdr),
                 comp_ehdr.e_shoff + i * sizeof(Elf64_Shdr));

        if (curr_shdr.sh_type == SHT_SYMTAB)
        {
            comp_symtb_shdr = curr_shdr;
            found_headers += 1;
        }
        // Lookup `.rela.plt` to eagerly load relocatable function addresses
        else if (curr_shdr.sh_type == SHT_RELA &&
                 !strcmp(&comp_sh_strtb[curr_shdr.sh_name], ".rela.plt"))
        {
            comp_rela_plt_shdr = curr_shdr;
            found_headers += 1;
        }
        // Lookup `.dynamic` to find library dependencies
        else if (curr_shdr.sh_type == SHT_DYNAMIC)
        {
            comp_dynamic_shdr = curr_shdr;
            found_headers += 1;
        }

        if (headers_of_interest_count == found_headers)
        {
            break;
        }
    }
    assert(headers_of_interest_count == found_headers);

    if (new_comp->elf_type == ET_DYN)
    {
        // Traverse `.rela.plt`, so we can see which function addresses we need
        // to eagerly load
        Elf64_Rela* comp_rela_plt = malloc(comp_rela_plt_shdr.sh_size);
        do_pread((int) new_comp->fd, comp_rela_plt, comp_rela_plt_shdr.sh_size,
                 comp_rela_plt_shdr.sh_offset);
        size_t rela_count = comp_rela_plt_shdr.sh_size / sizeof(Elf64_Rela);

        Elf64_Shdr dyn_sym_hdr;
        do_pread((int) new_comp->fd, &dyn_sym_hdr,
                 sizeof(Elf64_Shdr),
                 comp_ehdr.e_shoff + comp_rela_plt_shdr.sh_link * sizeof(Elf64_Shdr));
        Elf64_Sym* dyn_sym_tbl = malloc(dyn_sym_hdr.sh_size);
        do_pread((int) new_comp->fd, dyn_sym_tbl, dyn_sym_hdr.sh_size,
                 dyn_sym_hdr.sh_offset);

        Elf64_Shdr dyn_str_hdr;
        do_pread((int) new_comp->fd, &dyn_str_hdr,
                 sizeof(Elf64_Shdr),
                 comp_ehdr.e_shoff + dyn_sym_hdr.sh_link * sizeof(Elf64_Shdr));
        char* dyn_str_tbl = malloc(dyn_str_hdr.sh_size);
        do_pread((int) new_comp->fd, dyn_str_tbl, dyn_str_hdr.sh_size,
                 dyn_str_hdr.sh_offset);

        new_comp->rela_maps = calloc(rela_count, sizeof(struct CompRelaMapping));
        new_comp->rela_maps_count = rela_count;

        // Log symbols that will need to be relocated eagerly at maptime
        Elf64_Rela curr_rela;
        for (size_t j = 0; j < new_comp->rela_maps_count; ++j)
        {
            curr_rela = comp_rela_plt[j];
            size_t curr_rela_sym_idx = ELF64_R_SYM(curr_rela.r_info);
            Elf64_Sym curr_rela_sym = dyn_sym_tbl[curr_rela_sym_idx];
            char* curr_rela_name = malloc(strlen(&dyn_str_tbl[curr_rela_sym.st_name]) + 1);
            strcpy(curr_rela_name, &dyn_str_tbl[curr_rela_sym.st_name]);
            if (ELF64_ST_BIND(curr_rela_sym.st_info) == STB_WEAK)
            {
                // Do not handle weak-bind symbols
                // TODO should we?
                struct CompRelaMapping crm = { curr_rela_name, 0, 0 };
                new_comp->rela_maps[j] = crm;
                continue;
            } // TODO collapse

            struct CompRelaMapping crm = {
                curr_rela_name,
                curr_rela.r_offset + (char*) new_comp->base,
                NULL };
            new_comp->rela_maps[j] = crm;
        }
        free(comp_rela_plt);
        free(dyn_sym_tbl);

        // Find additional library dependencies
        Elf64_Dyn* comp_dyn_entries = malloc(comp_dynamic_shdr.sh_size);
        do_pread((int) new_comp->fd, comp_dyn_entries,
                 comp_dynamic_shdr.sh_size, comp_dynamic_shdr.sh_offset);

        for (size_t i = 0;
             i < comp_dynamic_shdr.sh_size / sizeof(Elf64_Dyn);
             ++i)
        {
            if (comp_dyn_entries[i].d_tag == DT_NEEDED)
            {
                struct LibDependency* new_lib_dep =
                    malloc(sizeof(struct LibDependency));
                new_lib_dep->lib_name =
                    malloc(strlen(&dyn_str_tbl[comp_dyn_entries[i].d_un.d_val]) + 1);
                strcpy(
                    new_lib_dep->lib_name,
                    &dyn_str_tbl[comp_dyn_entries[i].d_un.d_val]);
                new_comp->lib_deps_count += 1;
                new_comp->lib_deps =
                    realloc(new_comp->lib_deps,
                            new_comp->lib_deps_count *
                                sizeof(struct LibDependency));
                new_comp->lib_deps[new_comp->lib_deps_count - 1] = new_lib_dep;
            }
        }

        free(dyn_str_tbl);
        free(comp_dyn_entries);
    }

    // Find library files in `COMP_LIBRARY_PATH` to fulfill dependencies
    for (size_t i = 0; i < new_comp->lib_deps_count; ++i)
    {
        struct LibDependency* curr_dep = new_comp->lib_deps[i];
        // TODO move env var name to constant
        assert(getenv("COMP_LIBRARY_PATH"));
        char* lib_path =
            find_in_dir(curr_dep->lib_name, getenv("COMP_LIBRARY_PATH"));
        if (!lib_path)
        {
            errx(1, "Could not find file for dependency %s!\n", curr_dep->lib_name);
        }
        curr_dep->lib_path = malloc(strlen(lib_path));
        strcpy(curr_dep->lib_path, lib_path);
        init_lib_dep_info(curr_dep, new_comp);
        new_comp->mem_top =
            (char*) curr_dep->lib_mem_base +
            (uintptr_t) curr_dep->lib_segs[curr_dep->lib_segs_count - 1]->mem_top;
    }

    // Find functions of interest, particularly entry points, and functions to
    // intercept
    Elf64_Shdr comp_strtb_hdr;
    do_pread((int) new_comp->fd, &comp_strtb_hdr, sizeof(Elf64_Shdr),
        comp_ehdr.e_shoff + comp_symtb_shdr.sh_link * sizeof(Elf64_Shdr));

    // XXX The string table is read in `comp_strtb` as a sequence of
    // variable-length strings. Then, symbol names are obtained by indexing at
    // the offset where the name for that symbol begins. Therefore, the type
    // `char*` for the string table makes sense.
    char* comp_strtb = malloc(comp_strtb_hdr.sh_size);
    do_pread((int) new_comp->fd, comp_strtb, comp_strtb_hdr.sh_size, comp_strtb_hdr.sh_offset);

    Elf64_Sym* comp_symtb = malloc(comp_symtb_shdr.sh_size);
    do_pread((int) new_comp->fd, comp_symtb, comp_symtb_shdr.sh_size, comp_symtb_shdr.sh_offset);

    // Find symbols for entry_points
    Elf64_Sym* ep_syms =
        find_symbols((const char**) entry_points, entry_point_count,
                     true, comp_symtb, comp_strtb, comp_symtb_shdr.sh_size);
    for (size_t i = 0; i < entry_point_count; ++i)
    {
        struct entry_point* new_entry_point = malloc(sizeof(struct entry_point));
        new_entry_point->fn_name = entry_points[i];
        switch(new_comp->elf_type)
        {
            case ET_DYN:
            {
                new_entry_point->fn_addr = (char*) new_comp->base + ep_syms[i].st_value;
                break;
            }
            case ET_EXEC:
            {
                new_entry_point->fn_addr = (void*) ep_syms[i].st_value;
                break;
            }
            default:
                errx(1, "Invalid ELF type");
        }
        new_comp->comp_fns[new_comp->entry_point_count] = new_entry_point;
        new_comp->entry_point_count += 1;
    }
    free(ep_syms);

    // Find symbols for intercepts
    char** intercept_names = calloc(intercept_count, sizeof(char*));
    const char* so_plt_suffix = "@plt";
    for (size_t i = 0; i < intercept_count; ++i)
    {
        if (new_comp->elf_type == ET_DYN)
        {
            size_t to_intercept_name_len = strlen(intercepts[i]) + strlen(so_plt_suffix) + 1;
            intercept_names[i] = malloc(to_intercept_name_len);
            strcpy(intercept_names[i], intercepts[i]);
            strcat(intercept_names[i], so_plt_suffix);
        }
        else if (new_comp->elf_type == ET_EXEC)
        {
            intercept_names[i] = malloc(strlen(intercepts[i]) + 1);
            strcpy(intercept_names[i], intercepts[i]);
        }
        else
        {
            errx(1, "Invalid ELF type");
        }
    }
    Elf64_Sym* intercept_syms =
        find_symbols((const char**) intercept_names, intercept_count, false,
                     comp_symtb, comp_strtb, comp_symtb_shdr.sh_size);
    for (size_t i = 0; i < intercept_count; ++i)
    {
        // TODO better way to check if we didn't find an intercept?
        if (intercept_syms[i].st_value != 0)
        {
            comp_add_intercept(new_comp, intercept_syms[i].st_value, (uintptr_t) intercept_addrs[i]);
        }
        free(intercept_names[i]);
    }
    free(intercept_names);
    free(intercept_syms);

    // Find all symbols for eager relocation mapping
    for (size_t i = 0; i < new_comp->rela_maps_count; ++i)
    {
        // Ignore relocations we don't want to load, as earlier set on lookup
        // (e.g., weak-bound symbols)
        if (new_comp->rela_maps[i].rela_address == 0)
        {
            continue;
        }
        for (size_t j = 0; j < new_comp->lib_deps_count; ++j)
        {
            for (size_t k = 0; k < new_comp->lib_deps[j]->lib_syms_count; ++k)
            {
                if (!strcmp(new_comp->rela_maps[i].rela_name,
                            new_comp->lib_deps[j]->lib_syms[k].sym_name))
                {
                    new_comp->rela_maps[i].target_func_address =
                        (char*) new_comp->lib_deps[j]->lib_mem_base +
                        new_comp->lib_deps[j]->lib_syms[k].sym_offset;
                    goto found;
                }
            }
        }
        errx(1, "Did not find symbol %s!\n", new_comp->rela_maps[i].rela_name);
        found:
            (void) 0;
    }

    free(comp_symtb);
    free(comp_strtb);

    return new_comp;
}

/* For a given Compartment `new_comp`, an address `intercept_target` pointing
 * to a function found within the compartment which we would like to intercept,
 * and a `intercept_data` struct representing information to perform the
 * intercept, synthesize and inject intructions at the call point of the
 * `intercept_target`, in order to perform a transition out of the compartment
 * to call the appropriate function with higher privileges.
 */
void
comp_add_intercept(struct Compartment* new_comp, uintptr_t intercept_target, uintptr_t redirect_addr)
{
    // TODO check whether negative values break anything in all these generated functions
    int32_t new_instrs[INTERCEPT_INSTR_COUNT];
    size_t new_instr_idx = 0;
    const ptraddr_t comp_manager_cap_addr =
        (ptraddr_t) new_comp->manager_caps +
        new_comp->active_manager_caps_count * sizeof(void* __capability); // TODO

    const int32_t arm_function_target_register = 0b01010; // use `x10` for now
    const int32_t arm_transition_target_register = 0b01011; // use `x11` for now

    // `x10` is used to hold the address of the manager function we want to
    // execute after a jump out of the compartment
    // TODO ideally we want 1 `movz` and 3 `movk`, to be able to access any
    // address, but this is sufficient for now
    // movz x0, $target_fn_addr:lo16
    // movk x0, $target_fn_addr:hi16
    assert(intercept_target < ((ptraddr_t) 1 << 32));
    const uint32_t arm_movz_instr_mask = 0b11010010100 << 21;
    const uint32_t arm_movk_instr_mask = 0b11110010101 << 21;
    const ptraddr_t target_address_lo16 = (redirect_addr & ((1 << 16) - 1)) << 5;
    const ptraddr_t target_address_hi16 = (redirect_addr >> 16) << 5;
    const int32_t arm_movz_intr = arm_movz_instr_mask | target_address_lo16 | arm_function_target_register;
    const int32_t arm_movk_intr = arm_movk_instr_mask | target_address_hi16 | arm_function_target_register;
    new_instrs[new_instr_idx++] = arm_movz_intr;
    new_instrs[new_instr_idx++] = arm_movk_intr;

    /* `ldpbr` instr generation */
    // TODO do we have space to insert these instructions?
    // TODO what if we need to jump more than 4GB away?
    // Use `adrp` to get address close to address of manager capability required
    // adrp x11, $OFFSET
    const uint32_t arm_adrp_instr_mask = 0b10010000 << 24;
    const ptraddr_t target_address = (comp_manager_cap_addr >> 12) - (intercept_target >> 12);
    assert(target_address < ((ptraddr_t) 1 << 32));
    const int32_t arm_adrp_immlo = (target_address & 0b11) << 29;
    const int32_t arm_adrp_immhi = (target_address >> 2) <<  5;
    const int32_t arm_adrp_instr = arm_adrp_instr_mask | arm_adrp_immlo | arm_adrp_immhi | arm_transition_target_register;
    new_instrs[new_instr_idx++] = arm_adrp_instr;

    // `ldr` capability within compartment pointing to manager capabilities
    // ldr (unsigned offset, capability, normal base)
    // `ldr c11, [x11, $OFFSET]`
    const uint32_t arm_ldr_instr_mask = 0b1100001001 << 22; // includes 0b00 bits for `op` field
    ptraddr_t arm_ldr_pcc_offset = comp_manager_cap_addr; // offset within 4KB page
    ptraddr_t offset_correction = align_down(comp_manager_cap_addr, 1 << 12);
    arm_ldr_pcc_offset -= offset_correction;

    assert(arm_ldr_pcc_offset < 65520); // from ISA documentation
    assert(arm_ldr_pcc_offset % 16 == 0);
    arm_ldr_pcc_offset = arm_ldr_pcc_offset << 10;
    const int32_t arm_ldr_base_register = arm_transition_target_register << 5; // use `x11` for now
    const int32_t arm_ldr_dest_register = arm_transition_target_register; // use `c11` for now
    const int32_t arm_ldr_instr = arm_ldr_instr_mask | arm_ldr_pcc_offset | arm_ldr_base_register | arm_ldr_dest_register;
    new_instrs[new_instr_idx++] = arm_ldr_instr;

    // `b` instr generation
    ptraddr_t arm_b_instr_offset = (((uintptr_t) new_comp->mng_trans_fn) - (intercept_target + new_instr_idx * sizeof(uint32_t))) / 4;
    assert(arm_b_instr_offset < (1 << 27));
    arm_b_instr_offset &= (1 << 26) - 1;
    const uint32_t arm_b_instr_mask = 0b101 << 26;
    uintptr_t arm_b_instr = arm_b_instr_mask | arm_b_instr_offset;
    new_instrs[new_instr_idx++] = arm_b_instr;

    assert(new_instr_idx == INTERCEPT_INSTR_COUNT);
    struct intercept_patch new_patch;
    new_patch.patch_addr = (void*) intercept_target;
    memcpy(new_patch.instr, new_instrs, sizeof(new_instrs));
    __clear_cache(new_patch.instr, new_patch.instr + sizeof(new_instrs));
    new_patch.comp_manager_cap_addr = comp_manager_cap_addr;
    new_patch.manager_cap = sealed_redirect_cap;
    new_comp->curr_intercept_count += 1;
    new_comp->intercept_patches = realloc(new_comp->intercept_patches, new_comp->curr_intercept_count * sizeof(struct intercept_patch));
    new_comp->intercept_patches[new_comp->curr_intercept_count - 1] = new_patch;
}

void
comp_stack_push(struct Compartment* comp, const void* to_push, size_t to_push_sz)
{
    comp->stack_pointer = (char*) comp->stack_pointer - to_push_sz;
    memcpy((void*) comp->stack_pointer, to_push, to_push_sz);
    assert(comp->stack_pointer > (void*) ((char*) comp->scratch_mem_stack_top - comp->scratch_mem_stack_size));
}

/* Map a struct Compartment into memory, making it ready for execution
 */
void
comp_map(struct Compartment* to_map)
{
    assert(!(to_map->mapped || to_map->mapped_full));
    struct SegmentMap* curr_seg;
    void* map_result;

    // Map compartment segments
    for (size_t i = 0; i < to_map->seg_count; ++i)
    {
        curr_seg = to_map->segs[i];
        map_result = mmap((void*) curr_seg->mem_bot,
                                curr_seg->mem_sz,
                                /*curr_seg->prot_flags,*/ // TODO currently need read/write to inject the intercepts, consider better option
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                                -1, 0);
        if (map_result == MAP_FAILED)
        {
            errx(1, "Error mapping comp segment idx %zu", i);
        }
        do_pread(to_map->fd, (void*) curr_seg->mem_bot, curr_seg->file_sz,
                 curr_seg->offset);
    }

    // Map compartment library dependencies segments
    struct LibDependency* lib_dep;
    struct SegmentMap* lib_dep_seg;
    int lib_dep_fd;
    for (size_t i = 0; i < to_map->lib_deps_count; ++i)
    {
        lib_dep = to_map->lib_deps[i];
        lib_dep_fd = open(lib_dep->lib_path, O_RDONLY);
        for (size_t j = 0; j < lib_dep->lib_segs_count; ++j)
        {
            lib_dep_seg = lib_dep->lib_segs[j];
            map_result = mmap((char*) lib_dep->lib_mem_base + (uintptr_t) lib_dep_seg->mem_bot,
                              lib_dep_seg->mem_sz,
                              PROT_READ | PROT_WRITE | PROT_EXEC, // TODO fix
                              MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                              -1, 0);
            if (map_result == MAP_FAILED)
            {
                errx(1, "Error mapping library %s dependency segment idx %zu",
                        lib_dep->lib_name, j);
            }
            do_pread(lib_dep_fd, (char*) lib_dep->lib_mem_base + (uintptr_t) lib_dep_seg->mem_bot,
                     lib_dep_seg->file_sz, lib_dep_seg->offset);
        }
        close(lib_dep_fd);
    }

    // Map compartment scratch memory
    map_result = mmap((void*) to_map->scratch_mem_base,
                      to_map->scratch_mem_size,
                      PROT_READ | PROT_WRITE | PROT_EXEC, // TODO Fix this
                      MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                      -1, 0);
    assert(map_result != MAP_FAILED);

    // Map compartment stack
    map_result = mmap((char*) to_map->scratch_mem_stack_top - to_map->scratch_mem_stack_size,
                      to_map->scratch_mem_stack_size,
                      PROT_READ | PROT_WRITE | PROT_EXEC, // TODO fix this
                      MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_STACK,
                      -1, 0);
    to_map->stack_pointer = to_map->scratch_mem_stack_top;
    assert(map_result != MAP_FAILED);

    // Inject intercept instructions within identified intercepted functions
    for (size_t i = 0; i < to_map->curr_intercept_count; ++i)
    {
        struct intercept_patch to_patch = to_map->intercept_patches[i];
        // TODO change to memcpy?
        for (size_t j = 0; j < INTERCEPT_INSTR_COUNT; ++j)
        {
            int32_t* curr_addr = to_patch.patch_addr + j;
            *curr_addr = to_patch.instr[j];
        }
        *((void* __capability *) to_patch.comp_manager_cap_addr) = to_patch.manager_cap;
    }

    // Inject manager transfer function
    memcpy(to_map->mng_trans_fn, (void*) &compartment_transition_out, to_map->mng_trans_fn_sz);

    // Bind `.got.plt` entries
    for (size_t i = 0; i < to_map->rela_maps_count; ++i)
    {
        if (to_map->rela_maps[i].rela_address == 0)
        {
            continue;
        }
        memcpy((void*) to_map->rela_maps[i].rela_address,
               &to_map->rela_maps[i].target_func_address,
               sizeof(void*));
    }

    to_map->mapped = true;
}

void ddc_set(void *__capability cap) {
    assert(cap != NULL);
    asm volatile("MSR DDC, %[cap]" : : [cap] "C"(cap) : "memory");
}

/* Execute a mapped compartment, by jumping to the appropriate entry point.
 *
 * The entry point is given as a function name in the `fn_name` argument, and
 * arguments to be passed are tightly packed in `args`. The requested entry
 * point must have been registered prior during compartment initialization, by
 * calling `parse_compartment_config`, and passing an appropriate `.comp`
 * config file.
 *
 * TODO casually ignore the situation where no compartment is passed, if we
 * prefer to default to `main` in that case
 */
int64_t
comp_exec(struct Compartment* to_exec, char* fn_name, void* args, size_t args_count)
{
    assert(to_exec->mapped && "Attempting to execute an unmapped compartment.\n");

    void* fn = NULL;
    for (size_t i = 0; i < to_exec->entry_point_count; ++i)
    {
        if (!strcmp(fn_name, to_exec->comp_fns[i]->fn_name))
        {
            fn = (void*) to_exec->comp_fns[i]->fn_addr;
            break;
        }
    }
    if (!fn)
    {
        errx(1, "Did not find entry point `%s`!\n", fn_name);
    }
    void* wrap_sp;

    // TODO check if we need anything from here
    // https://git.morello-project.org/morello/kernel/linux/-/wikis/Morello-pure-capability-kernel-user-Linux-ABI-specification

    int64_t result;

    // TODO handle register clobbering stuff (`syscall-restrict` example)
    // https://github.com/capablevms/cheri_compartments/blob/master/code/signal_break.c#L46
    assert(args_count <= 3);
    // TODO attempt to lifting pointers to capabilities before passing to
    // compartments. Might be needed when handling pointers.
    /*void * __capability * args_caps;*/
    /*for (size_t i = 0; i < args_count; ++i)*/
    /*{*/
        /*void* __capability arg = (__cheri_tocap void* __capability) args[i];*/
        /*arg = cheri_perms_and(arg, !(CHERI_PERM_STORE | CHERI_PERM_EXECUTE));*/
        /*args_caps[i] = arg;*/
    /*}*/
    result = comp_exec_in((void*) to_exec->stack_pointer, to_exec->ddc, fn,
                          args, args_count, sealed_redirect_cap);
    return result;
}

void
comp_clean(struct Compartment* to_clean)
{
    close(to_clean->fd);
    if (to_clean->mapped)
    {
        // TODO unmap
    }
    else if (to_clean->mapped_full)
    {
        // TODO unmap
    }

    for (size_t i = 0; i < to_clean->seg_count; ++i)
    {
        free(to_clean->segs[i]);
    }
    free(to_clean->segs);

    for (size_t i = 0; i < to_clean->entry_point_count; ++i)
    {
        free((char*) to_clean->comp_fns[i]->fn_name);
        free(to_clean->comp_fns[i]);
    }

    for (size_t i = 0; i < to_clean->rela_maps_count; ++i)
    {
        free(to_clean->rela_maps[i].rela_name);
    }
    free(to_clean->rela_maps);

    struct LibDependency* ld;
    for (size_t i = 0; i < to_clean->lib_deps_count; ++i)
    {
        ld = to_clean->lib_deps[i];
        free(ld->lib_name);
        free(ld->lib_path);
        for (size_t j = 0; j < ld->lib_segs_count; ++j)
        {
            free(ld->lib_segs[j]);
        }
        free(ld->lib_segs);
        for (size_t j = 0; j < ld->lib_syms_count; ++j)
        {
            free(ld->lib_syms[j].sym_name);
        }
        free(ld->lib_syms);
        free(ld);
    }
    free(to_clean->lib_deps);
    free(to_clean->intercept_patches);


    free(to_clean);
    // TODO
}

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

static
ssize_t
do_pread(int fd, void* buf, size_t count, off_t offset)
{
    size_t res = pread(fd, buf, count, offset);
    if (res == -1)
    {
        err(1, "Error in pread");
    }
    return res;
}

static
Elf64_Sym*
find_symbols(const char** names, size_t names_to_find_count, bool find_all,
             Elf64_Sym* symtb, char* strtb, size_t symtb_sz)
{
    Elf64_Sym* found_syms = calloc(names_to_find_count, sizeof(Elf64_Sym));
    Elf64_Sym curr_sym;
    size_t found_syms_count = 0;
    for (size_t i = 0; i < symtb_sz / sizeof(Elf64_Sym); ++i)
    {
        curr_sym = symtb[i];
        for (size_t j = 0; j < names_to_find_count; ++j)
        {
            // XXX As a follow-up from how we handle the string table, here we
            // get symbol names by indexing at the `char` offset, then getting
            // the string pointer (equivalent to `strtb + curr_sym.st_name`).
            if (!strcmp(names[j], &strtb[curr_sym.st_name]))
            {
                found_syms[j] = curr_sym;
                found_syms_count += 1;
            }
        }
    }

    // If we didn't find all symbols that we wanted to intercept, throw an error
    if (find_all && found_syms_count != names_to_find_count)
    {
        const char** not_found_syms = malloc(names_to_find_count);
        size_t not_found_idx = 0;
        for (size_t i = 0; i < names_to_find_count; ++i)
        {
            bool not_found = true;
            for (size_t j = 0; j < found_syms_count; ++j)
            {
                if (!strcmp(&strtb[found_syms[j].st_name], names[i]))
                {
                    not_found = false;
                    break;
                }
            }
            if (not_found)
            {
                not_found_syms[not_found_idx] = names[i];
                not_found_idx += 1;
            }
        }
        printf("Did not find following entry points [ ");
        for (size_t i = 0; i < not_found_idx; ++i)
        {
            printf("%s ", not_found_syms[i]);
        }
        printf("]\n");
        free(not_found_syms);
        free(found_syms);
        errx(1, NULL);
    }

    return found_syms;
}

static
char*
find_in_dir(const char* lib_name, char* search_dir)
{
    errno = 0;
    char** search_paths = malloc(sizeof(char*));
    search_paths[0] = search_dir;
    FTS* dir = fts_open(search_paths, FTS_LOGICAL, NULL);
    if (!dir)
    {
        err(1, "Failed fts_open for path %s.\n", search_dir);
    }

    FTSENT* curr_entry;
    while ((curr_entry = fts_read(dir)) != NULL)
    {
        if (!strcmp(lib_name, curr_entry->fts_name))
        {
            return curr_entry->fts_path;
        }
    }
    fts_close(dir);
    free(search_paths);
    return NULL;
}

static
void
init_comp_scratch_mem(struct Compartment* new_comp)
{
    new_comp->scratch_mem_base =
        align_up(
            (char*) new_comp->segs[new_comp->seg_count - 1]->mem_top +
                new_comp->page_size,
            new_comp->page_size);
    new_comp->max_manager_caps_count = 10; // TODO
    new_comp->scratch_mem_heap_size = 0x800000UL; // TODO
    new_comp->scratch_mem_size =
            new_comp->scratch_mem_heap_size +
            new_comp->max_manager_caps_count * sizeof(void* __capability) +
            new_comp->mng_trans_fn_sz;
    new_comp->scratch_mem_alloc = 0;
    new_comp->scratch_mem_stack_top =
        align_down(
            (char*) new_comp->scratch_mem_base +
                new_comp->scratch_mem_heap_size,
            16);
    new_comp->scratch_mem_stack_size = 0x80000UL; // TODO
    new_comp->manager_caps = new_comp->scratch_mem_stack_top;
    new_comp->active_manager_caps_count = 0;
    new_comp->mng_trans_fn =
        (char*) new_comp->manager_caps +
        new_comp->max_manager_caps_count * sizeof(void* __capability);

    assert(((uintptr_t) new_comp->scratch_mem_base) % 16 == 0);
    assert((((uintptr_t) new_comp->scratch_mem_base) + new_comp->scratch_mem_size) % 16 == 0);
    assert(((uintptr_t) new_comp->scratch_mem_stack_top) % 16 == 0);
    assert(
        (((uintptr_t) new_comp->scratch_mem_stack_top) -
            new_comp->scratch_mem_stack_size) % 16 == 0);
    assert(new_comp->scratch_mem_size % 16 == 0);
}

/* Get the segment data for segments we will be mapping for a library dependency
 */
static
void
init_lib_dep_info(struct LibDependency* lib_dep, struct Compartment* new_comp)
{
    lib_dep->lib_segs_count = 0;
    int lib_fd = open(lib_dep->lib_path, O_RDONLY);
    assert(lib_fd != -1 && "Error opening `lib_fd`");
    Elf64_Ehdr lib_ehdr;
    Elf64_Phdr lib_phdr;
    do_pread(lib_fd, &lib_ehdr, sizeof(Elf64_Ehdr), 0);

    // Get segment data
    for (size_t i = 0; i < lib_ehdr.e_phnum; ++i)
    {
        do_pread((int) lib_fd, &lib_phdr, sizeof(Elf64_Phdr),
                 lib_ehdr.e_phoff + i * sizeof(lib_phdr));
        if (lib_phdr.p_type != PT_LOAD)
        {
            continue;
        }

        struct SegmentMap* this_seg = malloc(sizeof(struct SegmentMap));
        this_seg->mem_bot = (void*) align_down(lib_phdr.p_vaddr, new_comp->page_size);
        this_seg->correction = (char*) lib_phdr.p_vaddr - (char*) this_seg->mem_bot;
        this_seg->mem_top = (char*) lib_phdr.p_vaddr + lib_phdr.p_memsz;
        this_seg->offset = align_down(lib_phdr.p_offset, new_comp->page_size);
        this_seg->mem_sz = lib_phdr.p_memsz + this_seg->correction;
        this_seg->file_sz = lib_phdr.p_filesz + this_seg->correction;
        this_seg->prot_flags = (lib_phdr.p_flags & PF_R ? PROT_READ : 0) |
                                (lib_phdr.p_flags & PF_W ? PROT_WRITE : 0) |
                                (lib_phdr.p_flags & PF_X ? PROT_EXEC : 0);

        lib_dep->lib_segs_count += 1;
        lib_dep->lib_segs_size += align_up(this_seg->mem_sz, lib_phdr.p_align); // TODO check
        lib_dep->lib_segs =
            realloc(lib_dep->lib_segs,
                    lib_dep->lib_segs_count * sizeof(struct SegmentMap));
        lib_dep->lib_segs[lib_dep->lib_segs_count - 1] = this_seg;
    }

    lib_dep->lib_mem_base =
        align_down((char*) new_comp->mem_top + new_comp->page_size, new_comp->page_size);
    new_comp->size += new_comp->page_size + lib_dep->lib_segs_size;

    // Get symbol table
    Elf64_Shdr curr_shdr;
    Elf64_Shdr link_shdr;
    Elf64_Sym curr_sym;
    for (size_t i = 0; i < lib_ehdr.e_shnum; ++i)
    {
        do_pread((int) lib_fd, &curr_shdr, sizeof(Elf64_Shdr),
                 lib_ehdr.e_shoff + i * sizeof(Elf64_Shdr));
        if (curr_shdr.sh_type != SHT_SYMTAB)
        {
            continue;
        }

        assert(curr_shdr.sh_link);
        do_pread((int) lib_fd, &link_shdr, sizeof(Elf64_Shdr),
                 lib_ehdr.e_shoff + curr_shdr.sh_link * sizeof(Elf64_Shdr));

        Elf64_Sym* sym_tb = malloc(curr_shdr.sh_size);
        do_pread((int) lib_fd, sym_tb, curr_shdr.sh_size, curr_shdr.sh_offset);
        char* str_tb = malloc(link_shdr.sh_size);
        do_pread((int) lib_fd, str_tb, link_shdr.sh_size, link_shdr.sh_offset);

        lib_dep->lib_syms_count = curr_shdr.sh_size / sizeof(Elf64_Sym);
        size_t actual_syms = 0;
        struct LibDependencySymbol* ld_syms =
            malloc(lib_dep->lib_syms_count * sizeof(struct LibDependencySymbol));
        for (size_t j = 0; j < lib_dep->lib_syms_count; ++j)
        {
            curr_sym = sym_tb[j];
            // TODO only handling FUNC symbols for now
            if (ELF64_ST_TYPE(curr_sym.st_info) != STT_FUNC)
            {
                continue;
            }
            if (curr_sym.st_value == 0)
            {
                continue;
            }
            ld_syms[actual_syms].sym_offset = curr_sym.st_value;
            char* sym_name = &str_tb[curr_sym.st_name];
            ld_syms[actual_syms].sym_name = malloc(strlen(sym_name) + 1);
            strcpy(ld_syms[actual_syms].sym_name, sym_name);
            actual_syms += 1;
        }
        ld_syms = realloc(ld_syms, actual_syms * sizeof(struct LibDependencySymbol));
        lib_dep->lib_syms_count = actual_syms;
        lib_dep->lib_syms = ld_syms;

        free(sym_tb);
        free(str_tb);
    }

    close(lib_fd);
}
