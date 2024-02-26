#include "compartment.h"

const char *libs_path_env_var = "COMP_LIBRARY_PATH";

/*******************************************************************************
 * Forward declarations
 ******************************************************************************/

static void
get_lib_name(struct LibDependency *, const char *);
static struct LibDependency *
parse_lib_file(char *, struct Compartment *);
static void
parse_lib_segs(Elf64_Ehdr *, int, struct LibDependency *, struct Compartment *);
static void
parse_lib_symtb(Elf64_Shdr *, Elf64_Ehdr *, int, struct LibDependency *);
static void
parse_lib_relaplt(Elf64_Shdr *, Elf64_Ehdr *, int, struct LibDependency *);
static void
parse_lib_dynamic_deps(Elf64_Shdr *, Elf64_Ehdr *, int, struct LibDependency *);
static void
find_comp_entry_points(char **, size_t, struct Compartment *);
static void
find_comp_intercepts(char **, void **, size_t, struct Compartment *);
static void
resolve_rela_syms(struct Compartment *);
static struct LibSymSearchResult
find_lib_dep_sym_in_comp(const char *, struct Compartment *);
static void *
extract_sym_offset(struct Compartment *, struct LibSymSearchResult);

static ssize_t
do_pread(int, void *, size_t, off_t);
static char *
find_in_dir(const char *, char *);
static void
init_comp_scratch_mem(struct Compartment *);

static void
print_lib_dep_seg(struct SegmentMap *);
static void
print_lib_dep(struct LibDependency *);

/*******************************************************************************
 * Main compartment functions
 ******************************************************************************/

/* Initialize some values of the Compartment struct. The rest are expected to
 * be set in `comp_from_elf`.
 */
struct Compartment *
comp_init()
{
    // TODO order
    struct Compartment *new_comp
        = (struct Compartment *) malloc(sizeof(struct Compartment));

    new_comp->ddc = NULL;

    new_comp->size = 0;
    new_comp->base = NULL;
    new_comp->mem_top = NULL;
    new_comp->mapped = false;

    new_comp->scratch_mem_base = NULL;
    new_comp->scratch_mem_size = 0;
    new_comp->scratch_mem_alloc = 0;

    new_comp->scratch_mem_heap_size = 0;
    new_comp->scratch_mem_stack_top = NULL;
    new_comp->scratch_mem_stack_size = 0;
    new_comp->stack_pointer = NULL;
    new_comp->alloc_head = NULL;

    new_comp->manager_caps = NULL;
    new_comp->max_manager_caps_count = 0;
    new_comp->active_manager_caps_count = 0;

    new_comp->mng_trans_fn = NULL;
    new_comp->mng_trans_fn_sz
        = sizeof(uint32_t) * COMP_TRANS_FN_INSTR_CNT; // TODO ptr arithmetic

    new_comp->libs_count = 0;
    new_comp->libs = NULL;
    new_comp->entry_point_count = 0;
    new_comp->entry_points = NULL;

    new_comp->page_size = sysconf(_SC_PAGESIZE);

    new_comp->curr_intercept_count = 0;
    new_comp->intercept_patches = NULL;

    return new_comp;
}

/* Comparison function for `struct CompEntryPoint`
 */
int
entry_point_cmp(const void *val1, const void *val2)
{
    struct CompEntryPoint *ep1 = *(struct CompEntryPoint **) val1;
    struct CompEntryPoint *ep2 = *(struct CompEntryPoint **) val2;
    return strcmp(ep1->fn_name, ep2->fn_name);
}

/* Give a binary ELF file in `filename`, read the ELF data and store it within
 * a `struct Compartment`. At this point, we only read data.
 */
struct Compartment *
comp_from_elf(char *filename, char **entry_points, size_t entry_point_count,
    char **intercepts, void **intercept_addrs, size_t intercept_count,
    void *new_comp_base)
{
    struct Compartment *new_comp = comp_init();
    new_comp->base = new_comp_base;
    new_comp->mem_top = new_comp_base;

    unsigned short libs_to_parse_count = 1;
    unsigned short libs_parsed_count = 0;
    char **libs_to_parse = malloc(sizeof(char *));
    libs_to_parse[0] = filename;

    char *libs_folder = getenv(libs_path_env_var);

    while (libs_parsed_count != libs_to_parse_count)
    {
        struct LibDependency *parsed_lib
            = parse_lib_file(libs_to_parse[libs_parsed_count], new_comp);

        const unsigned short libs_to_search_count = libs_to_parse_count;
        for (size_t i = 0; i < parsed_lib->lib_dep_count; ++i)
        {
            for (size_t j = 0; j < libs_to_search_count; ++j)
            {
                if (!strcmp(libs_to_parse[j], parsed_lib->lib_dep_names[i]))
                {
                    goto next_dep;
                }
            }
            libs_to_parse = realloc(
                libs_to_parse, (libs_to_parse_count + 1) * sizeof(char *));
            libs_to_parse[libs_to_parse_count] = parsed_lib->lib_dep_names[i];
            libs_to_parse_count += 1;
            // TODO check performance with goto versus without
        next_dep:
            (void) 0;
        }
        libs_parsed_count += 1;
    }
    free(libs_to_parse);

    assert(entry_points);
    assert(entry_point_count > 0);

    init_comp_scratch_mem(new_comp);
    new_comp->mem_top = new_comp->scratch_mem_stack_top;

    find_comp_entry_points(entry_points, entry_point_count, new_comp);
    find_comp_intercepts(
        intercepts, intercept_addrs, intercept_count, new_comp);
    resolve_rela_syms(new_comp);

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
comp_add_intercept(struct Compartment *new_comp, uintptr_t intercept_target,
    uintptr_t redirect_addr)
{
    // TODO check whether negative values break anything in all these generated
    // functions
    int32_t new_instrs[INTERCEPT_INSTR_COUNT];
    size_t new_instr_idx = 0;
    const ptraddr_t comp_manager_cap_addr = (ptraddr_t) new_comp->manager_caps
        + new_comp->active_manager_caps_count
            * sizeof(void *__capability); // TODO

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
    const ptraddr_t target_address_lo16 = (redirect_addr & ((1 << 16) - 1))
        << 5;
    const ptraddr_t target_address_hi16 = (redirect_addr >> 16) << 5;
    const int32_t arm_movz_intr = arm_movz_instr_mask | target_address_lo16
        | arm_function_target_register;
    const int32_t arm_movk_intr = arm_movk_instr_mask | target_address_hi16
        | arm_function_target_register;
    new_instrs[new_instr_idx++] = arm_movz_intr;
    new_instrs[new_instr_idx++] = arm_movk_intr;

    /* `ldpbr` instr generation */
    // TODO do we have space to insert these instructions?
    // TODO what if we need to jump more than 4GB away?
    // Use `adrp` to get address close to address of manager capability required
    // adrp x11, $OFFSET
    const uint32_t arm_adrp_instr_mask = 0b10010000 << 24;
    const ptraddr_t target_address
        = (comp_manager_cap_addr >> 12) - (intercept_target >> 12);
    assert(target_address < ((ptraddr_t) 1 << 32));
    const int32_t arm_adrp_immlo = (target_address & 0b11) << 29;
    const int32_t arm_adrp_immhi = (target_address >> 2) << 5;
    const int32_t arm_adrp_instr = arm_adrp_instr_mask | arm_adrp_immlo
        | arm_adrp_immhi | arm_transition_target_register;
    new_instrs[new_instr_idx++] = arm_adrp_instr;

    // `ldr` capability within compartment pointing to manager capabilities
    // ldr (unsigned offset, capability, normal base)
    // `ldr c11, [x11, $OFFSET]`
    const uint32_t arm_ldr_instr_mask = 0b1100001001
        << 22; // includes 0b00 bits for `op` field
    ptraddr_t arm_ldr_pcc_offset
        = comp_manager_cap_addr; // offset within 4KB page
    ptraddr_t offset_correction = align_down(comp_manager_cap_addr, 1 << 12);
    arm_ldr_pcc_offset -= offset_correction;

    assert(arm_ldr_pcc_offset < 65520); // from ISA documentation
    assert(arm_ldr_pcc_offset % 16 == 0);
    arm_ldr_pcc_offset = arm_ldr_pcc_offset << 10;
    const int32_t arm_ldr_base_register = arm_transition_target_register
        << 5; // use `x11` for now
    const int32_t arm_ldr_dest_register
        = arm_transition_target_register; // use `c11` for now
    const int32_t arm_ldr_instr = arm_ldr_instr_mask | arm_ldr_pcc_offset
        | arm_ldr_base_register | arm_ldr_dest_register;
    new_instrs[new_instr_idx++] = arm_ldr_instr;

    // `b` instr generation
    ptraddr_t arm_b_instr_offset
        = (((uintptr_t) new_comp->mng_trans_fn)
              - (intercept_target + new_instr_idx * sizeof(uint32_t)))
        / 4;
    assert(arm_b_instr_offset < (1 << 27));
    arm_b_instr_offset &= (1 << 26) - 1;
    const uint32_t arm_b_instr_mask = 0b101 << 26;
    uintptr_t arm_b_instr = arm_b_instr_mask | arm_b_instr_offset;
    new_instrs[new_instr_idx++] = arm_b_instr;

    assert(new_instr_idx == INTERCEPT_INSTR_COUNT);
    struct InterceptPatch new_patch;
    new_patch.patch_addr = (void *) intercept_target;
    memcpy(new_patch.instr, new_instrs, sizeof(new_instrs));
    __clear_cache(new_patch.instr, new_patch.instr + sizeof(new_instrs));
    new_patch.comp_manager_cap_addr = comp_manager_cap_addr;
    new_patch.manager_cap = sealed_redirect_cap;
    new_comp->curr_intercept_count += 1;
    new_comp->intercept_patches = realloc(new_comp->intercept_patches,
        new_comp->curr_intercept_count * sizeof(struct InterceptPatch));
    new_comp->intercept_patches[new_comp->curr_intercept_count - 1] = new_patch;
}

/* Map a struct Compartment into memory, making it ready for execution
 */
void
comp_map(struct Compartment *to_map)
{
    assert(!(to_map->mapped));
    struct SegmentMap *curr_seg;
    void *map_result;

    // Map compartment library dependencies segments
    struct LibDependency *lib_dep;
    struct SegmentMap lib_dep_seg;
    int lib_dep_fd;
    for (size_t i = 0; i < to_map->libs_count; ++i)
    {
        lib_dep = to_map->libs[i];
        lib_dep_fd = open(lib_dep->lib_path, O_RDONLY);
        for (size_t j = 0; j < lib_dep->lib_segs_count; ++j)
        {
            lib_dep_seg = lib_dep->lib_segs[j];
            map_result = mmap((char *) lib_dep->lib_mem_base
                    + (uintptr_t) lib_dep_seg.mem_bot,
                lib_dep_seg.mem_sz,
                PROT_READ | PROT_WRITE | PROT_EXEC, // TODO fix
                MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
            if (map_result == MAP_FAILED)
            {
                err(1, "Error mapping library %s dependency segment idx %zu!\n",
                    lib_dep->lib_name, j);
            }
            do_pread(lib_dep_fd,
                (char *) lib_dep->lib_mem_base
                    + (uintptr_t) lib_dep_seg.mem_bot,
                lib_dep_seg.file_sz, lib_dep_seg.offset);
        }
        close(lib_dep_fd);
    }

    // Map compartment scratch memory
    map_result
        = mmap((void *) to_map->scratch_mem_base, to_map->scratch_mem_size,
            PROT_READ | PROT_WRITE, // | PROT_EXEC, // TODO Fix this
            MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (map_result == MAP_FAILED)
    {
        err(1, "Error mapping compartment %zu scratch memory!\n", to_map->id);
    }

    // Map compartment stack
    map_result = mmap(
        (char *) to_map->scratch_mem_stack_top - to_map->scratch_mem_stack_size,
        to_map->scratch_mem_stack_size,
        PROT_READ | PROT_WRITE | PROT_EXEC, // TODO fix this
        MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    to_map->stack_pointer = to_map->scratch_mem_stack_top;
    if (map_result == MAP_FAILED)
    {
        err(1, "Error mapping compartment %zu stack!\n", to_map->id);
    }

    // Inject intercept instructions within identified intercepted functions
    for (unsigned short i = 0; i < to_map->curr_intercept_count; ++i)
    {
        struct InterceptPatch to_patch = to_map->intercept_patches[i];
        // TODO change to memcpy?
        for (size_t j = 0; j < INTERCEPT_INSTR_COUNT; ++j)
        {
            int32_t *curr_addr = to_patch.patch_addr + j;
            *curr_addr = to_patch.instr[j];
        }
        *((void *__capability *) to_patch.comp_manager_cap_addr)
            = to_patch.manager_cap;
    }

    // Inject manager transfer function
    memcpy(to_map->mng_trans_fn, (void *) &compartment_transition_out,
        to_map->mng_trans_fn_sz);

    // Bind `.got.plt` entries
    for (size_t i = 0; i < to_map->libs_count; ++i)
    {
        for (size_t j = 0; j < to_map->libs[i]->rela_maps_count; ++j)
        {
            if (to_map->libs[i]->rela_maps[j].rela_address == 0)
            {
                continue;
            }
            memcpy(to_map->libs[i]->rela_maps[j].rela_address,
                &to_map->libs[i]->rela_maps[j].target_func_address,
                sizeof(void *));
        }
    }

    to_map->mapped = true;
}

void
ddc_set(void *__capability cap)
{
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
comp_exec(
    struct Compartment *to_exec, char *fn_name, void *args, size_t args_count)
{
    assert(
        to_exec->mapped && "Attempting to execute an unmapped compartment.\n");

    void *fn = NULL;
    for (size_t i = 0; i < to_exec->entry_point_count; ++i)
    {
        if (!strcmp(fn_name, to_exec->entry_points[i].fn_name))
        {
            fn = (void *) to_exec->entry_points[i].fn_addr;
            break;
        }
    }
    if (!fn)
    {
        errx(1, "Did not find entry point `%s`!\n", fn_name);
    }
    void *wrap_sp;

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
    result = comp_exec_in(to_exec->stack_pointer, to_exec->ddc, fn, args,
        args_count, sealed_redirect_cap);
    return result;
}

void
comp_clean(struct Compartment *to_clean)
{
    if (to_clean->mapped)
    {
        // TODO unmap
    }

    struct LibDependency *curr_lib_dep;
    for (size_t i = 0; i < to_clean->libs_count; ++i)
    {
        size_t j;
        curr_lib_dep = to_clean->libs[i];

        // Clean library segments
        free(curr_lib_dep->lib_segs);

        // Clean library symbol data
        for (j = 0; j < curr_lib_dep->lib_syms_count; ++j)
        {
            free(curr_lib_dep->lib_syms[j].sym_name);
        }
        free(curr_lib_dep->lib_syms);

        // Clear library dependency names
        for (j = 0; j < curr_lib_dep->lib_dep_count; ++j)
        {
            free(curr_lib_dep->lib_dep_names[j]);
        }
        free(curr_lib_dep->lib_dep_names);

        // Clean library relocation mappings
        for (j = 0; j < curr_lib_dep->rela_maps_count; ++j)
        {
            free(curr_lib_dep->rela_maps[j].rela_name);
        }
        free(curr_lib_dep->rela_maps);

        free(curr_lib_dep->lib_name);
        free(curr_lib_dep->lib_path);
        free(curr_lib_dep);
    }
    free(to_clean->libs);
    free(to_clean->entry_points);
    free(to_clean->intercept_patches);
    free(to_clean);
}

/*******************************************************************************
 * Compartment library functions
 *
 * Functions dealing with parsing individual library files and correctly
 * placing them within a Compartment
 ******************************************************************************/

static struct LibDependency *
parse_lib_file(char *lib_name, struct Compartment *new_comp)
{
    int lib_fd = open(lib_name, O_RDONLY);
    char *lib_path = NULL;
    if (lib_fd == -1)
    {
        // Try to find the library in dependent paths
        // TODO currently only $COMP_LIBRARY_PATH
        lib_path = find_in_dir(lib_name, getenv(libs_path_env_var));
        lib_fd = open(lib_path, O_RDONLY);
        if (lib_fd == -1)
        {
            errx(1, "Error opening compartment file  %s!\n", lib_path);
        }
    }

    // Read ELF headers
    Elf64_Ehdr lib_ehdr;
    do_pread(lib_fd, &lib_ehdr, sizeof(Elf64_Ehdr), 0);
    if (lib_ehdr.e_type != ET_DYN)
    {
        errx(1,
            "Error parsing `%s` - only supporting ELFs of type DYN (shared "
            "object files)!\n",
            lib_path);
    }

    struct LibDependency *new_lib = malloc(sizeof(struct LibDependency));
    new_lib->lib_name = malloc(strlen(lib_name));
    strcpy(new_lib->lib_name, lib_name);
    if (lib_path)
    {
        new_lib->lib_path = malloc(strlen(lib_path));
        strcpy(new_lib->lib_path, lib_path);
    }
    else
    {
        new_lib->lib_path = malloc(strlen(lib_name));
        strcpy(new_lib->lib_path, lib_name);
    }

    // Initialization
    new_lib->lib_mem_base = NULL;

    new_lib->lib_segs_count = 0;
    new_lib->lib_segs_size = 0;
    new_lib->lib_segs = NULL;

    new_lib->lib_syms_count = 0;
    new_lib->lib_syms = NULL;

    new_lib->lib_dep_count = 0;
    new_lib->lib_dep_names = NULL;

    new_lib->rela_maps_count = 0;
    new_lib->rela_maps = NULL;

    parse_lib_segs(&lib_ehdr, lib_fd, new_lib, new_comp);

    // Load `.shstr` section, so we can check section names
    Elf64_Shdr shstrtab_hdr;
    do_pread(lib_fd, &shstrtab_hdr, sizeof(Elf64_Shdr),
        lib_ehdr.e_shoff + lib_ehdr.e_shstrndx * sizeof(Elf64_Shdr));
    char *shstrtab = malloc(shstrtab_hdr.sh_size);
    do_pread(lib_fd, shstrtab, shstrtab_hdr.sh_size, shstrtab_hdr.sh_offset);

    // XXX The string table is read in `strtab` as a sequence of
    // variable-length strings. Then, symbol names are obtained by indexing at
    // the offset where the name for that symbol begins. Therefore, the type
    // `char*` for the string table makes sense.
    //
    // Example:
    // -------------------------------
    // | "foo\0" | "bar\0" | "baz\0" |
    // -------------------------------
    //    0123      4567      89ab
    //
    // Symbol table entries will have the "name" value of the three
    // corresponding symbols as 0, 4, and 8.

    // Traverse sections once to get headers for sections of interest
    //
    // XXX According to the ELF specification version 1.2, for UNIX, there are
    // only one of each `SHT_SYMTAB`, `SHT_DYNSYM`, and `SHT_DYNAMIC`. Further,
    // we assume there can only be one section with the name `.rela.plt`.
    // Therefore, we expect each `if` to be only entered once. However, we not
    // that this can be changed in future specifications.
    //
    // Source: https://refspecs.linuxfoundation.org/elf/elf.pdf
    const size_t headers_of_interest_count = 3;
    size_t found_headers = 0;
    Elf64_Shdr curr_shdr;
    for (size_t i = 0; i < lib_ehdr.e_shnum; ++i)
    {
        do_pread(lib_fd, &curr_shdr, sizeof(Elf64_Shdr),
            lib_ehdr.e_shoff + i * sizeof(Elf64_Shdr));

        if (curr_shdr.sh_type == SHT_SYMTAB)
        {
            parse_lib_symtb(&curr_shdr, &lib_ehdr, lib_fd, new_lib);
            found_headers += 1;
        }
        // Lookup `.rela.plt` to eagerly load relocatable function addresses
        else if (curr_shdr.sh_type == SHT_RELA
            && !strcmp(&shstrtab[curr_shdr.sh_name], ".rela.plt"))
        {
            parse_lib_relaplt(&curr_shdr, &lib_ehdr, lib_fd, new_lib);
            found_headers += 1;
        }
        // Lookup `.dynamic` to find library dependencies
        else if (curr_shdr.sh_type == SHT_DYNAMIC)
        {
            parse_lib_dynamic_deps(&curr_shdr, &lib_ehdr, lib_fd, new_lib);
            found_headers += 1;
        }

        if (headers_of_interest_count == found_headers)
        {
            break;
        }
    }
    assert(headers_of_interest_count == found_headers);

    close(lib_fd);
    new_comp->libs_count += 1;
    new_comp->libs = realloc(
        new_comp->libs, new_comp->libs_count * sizeof(struct LibDependency *));
    new_comp->libs[new_comp->libs_count - 1] = new_lib;

    free(shstrtab);

    return new_lib;
}

static void
parse_lib_segs(Elf64_Ehdr *lib_ehdr, int lib_fd, struct LibDependency *lib_dep,
    struct Compartment *new_comp)
{
    // Get segment data
    Elf64_Phdr lib_phdr;
    for (size_t i = 0; i < lib_ehdr->e_phnum; ++i)
    {
        do_pread(lib_fd, &lib_phdr, sizeof(Elf64_Phdr),
            lib_ehdr->e_phoff + i * sizeof(lib_phdr));
        if (lib_phdr.p_type != PT_LOAD)
        {
            continue;
        }

        struct SegmentMap *this_seg = malloc(sizeof(struct SegmentMap));
        this_seg->mem_bot
            = (void *) align_down(lib_phdr.p_vaddr, new_comp->page_size);
        this_seg->correction
            = (char *) lib_phdr.p_vaddr - (char *) this_seg->mem_bot;
        this_seg->mem_top = (char *) lib_phdr.p_vaddr + lib_phdr.p_memsz;
        this_seg->offset = align_down(lib_phdr.p_offset, new_comp->page_size);
        this_seg->mem_sz = lib_phdr.p_memsz + this_seg->correction;
        this_seg->file_sz = lib_phdr.p_filesz + this_seg->correction;
        this_seg->prot_flags = (lib_phdr.p_flags & PF_R ? PROT_READ : 0)
            | (lib_phdr.p_flags & PF_W ? PROT_WRITE : 0)
            | (lib_phdr.p_flags & PF_X ? PROT_EXEC : 0);

        lib_dep->lib_segs_count += 1;
        lib_dep->lib_segs_size
            += align_up(this_seg->mem_sz, lib_phdr.p_align); // TODO check
        lib_dep->lib_segs = realloc(lib_dep->lib_segs,
            lib_dep->lib_segs_count * sizeof(struct SegmentMap));
        memcpy(&lib_dep->lib_segs[lib_dep->lib_segs_count - 1], this_seg,
            sizeof(struct SegmentMap));
        free(this_seg);
    }
    lib_dep->lib_mem_base = align_up(
        (char *) new_comp->mem_top + new_comp->page_size, new_comp->page_size);
    new_comp->size += lib_dep->lib_segs_size;
    new_comp->mem_top = (char *) lib_dep->lib_mem_base + lib_dep->lib_segs_size;
}

static void
parse_lib_symtb(Elf64_Shdr *symtb_shdr, Elf64_Ehdr *lib_ehdr, int lib_fd,
    struct LibDependency *lib_dep)
{
    // Get symbol table
    Elf64_Shdr link_shdr;
    assert(symtb_shdr->sh_link);
    do_pread(lib_fd, &link_shdr, sizeof(Elf64_Shdr),
        lib_ehdr->e_shoff + symtb_shdr->sh_link * sizeof(Elf64_Shdr));

    Elf64_Sym *sym_tb = malloc(symtb_shdr->sh_size);
    do_pread(lib_fd, sym_tb, symtb_shdr->sh_size, symtb_shdr->sh_offset);
    char *str_tb = malloc(link_shdr.sh_size);
    do_pread(lib_fd, str_tb, link_shdr.sh_size, link_shdr.sh_offset);

    lib_dep->lib_syms_count = symtb_shdr->sh_size / sizeof(Elf64_Sym);
    size_t actual_syms = 0;
    struct LibDependencySymbol *ld_syms
        = malloc(lib_dep->lib_syms_count * sizeof(struct LibDependencySymbol));

    Elf64_Sym curr_sym;
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
        ld_syms[actual_syms].sym_offset = (void *) curr_sym.st_value;
        char *sym_name = &str_tb[curr_sym.st_name];
        ld_syms[actual_syms].sym_name = malloc(strlen(sym_name) + 1);
        strcpy(ld_syms[actual_syms].sym_name, sym_name);
        actual_syms += 1;
    }
    ld_syms
        = realloc(ld_syms, actual_syms * sizeof(struct LibDependencySymbol));
    lib_dep->lib_syms_count = actual_syms;
    lib_dep->lib_syms = ld_syms;

    free(sym_tb);
    free(str_tb);
}

static void
parse_lib_relaplt(Elf64_Shdr *rela_plt_shdr, Elf64_Ehdr *lib_ehdr, int lib_fd,
    struct LibDependency *lib_dep)
{
    // Traverse `.rela.plt`, so we can see which function addresses we need
    // to eagerly load
    Elf64_Rela *rela_plt = malloc(rela_plt_shdr->sh_size);
    do_pread(
        lib_fd, rela_plt, rela_plt_shdr->sh_size, rela_plt_shdr->sh_offset);
    size_t rela_count = rela_plt_shdr->sh_size / sizeof(Elf64_Rela);

    Elf64_Shdr dyn_sym_hdr;
    do_pread(lib_fd, &dyn_sym_hdr, sizeof(Elf64_Shdr),
        lib_ehdr->e_shoff + rela_plt_shdr->sh_link * sizeof(Elf64_Shdr));
    Elf64_Sym *dyn_sym_tbl = malloc(dyn_sym_hdr.sh_size);
    do_pread(lib_fd, dyn_sym_tbl, dyn_sym_hdr.sh_size, dyn_sym_hdr.sh_offset);

    Elf64_Shdr dyn_str_hdr;
    do_pread(lib_fd, &dyn_str_hdr, sizeof(Elf64_Shdr),
        lib_ehdr->e_shoff + dyn_sym_hdr.sh_link * sizeof(Elf64_Shdr));
    char *dyn_str_tbl = malloc(dyn_str_hdr.sh_size);
    do_pread(lib_fd, dyn_str_tbl, dyn_str_hdr.sh_size, dyn_str_hdr.sh_offset);

    lib_dep->rela_maps = malloc(rela_count * sizeof(struct LibRelaMapping));
    lib_dep->rela_maps_count = rela_count;

    // Log symbols that will need to be relocated eagerly at maptime
    Elf64_Rela curr_rela;
    for (size_t j = 0; j < lib_dep->rela_maps_count; ++j)
    {
        curr_rela = rela_plt[j];
        size_t curr_rela_sym_idx = ELF64_R_SYM(curr_rela.r_info);
        Elf64_Sym curr_rela_sym = dyn_sym_tbl[curr_rela_sym_idx];
        char *curr_rela_name
            = malloc(strlen(&dyn_str_tbl[curr_rela_sym.st_name]) + 1);
        strcpy(curr_rela_name, &dyn_str_tbl[curr_rela_sym.st_name]);
        struct LibRelaMapping lrm;
        if (ELF64_ST_BIND(curr_rela_sym.st_info) == STB_WEAK)
        {
            // Do not handle weak-bind symbols
            // TODO should we?
            lrm = (struct LibRelaMapping) { curr_rela_name, 0, 0 };
        }
        else
        {
            lrm = (struct LibRelaMapping) { curr_rela_name,
                curr_rela.r_offset + (char *) lib_dep->lib_mem_base, NULL };
        }
        lib_dep->rela_maps[j] = lrm;
    }
    free(rela_plt);
    free(dyn_sym_tbl);
    free(dyn_str_tbl);
}

static void
parse_lib_dynamic_deps(Elf64_Shdr *dynamic_shdr, Elf64_Ehdr *lib_ehdr,
    int lib_fd, struct LibDependency *lib_dep)
{
    // Find additional library dependencies
    Elf64_Dyn *dyn_entries = malloc(dynamic_shdr->sh_size);
    do_pread(
        lib_fd, dyn_entries, dynamic_shdr->sh_size, dynamic_shdr->sh_offset);
    Elf64_Shdr dynstr_shdr;
    do_pread(lib_fd, &dynstr_shdr, sizeof(Elf64_Shdr),
        lib_ehdr->e_shoff + dynamic_shdr->sh_link * sizeof(Elf64_Shdr));
    char *dynstr_tbl = malloc(dynstr_shdr.sh_size);
    do_pread(lib_fd, dynstr_tbl, dynstr_shdr.sh_size, dynstr_shdr.sh_offset);

    for (size_t i = 0; i < dynamic_shdr->sh_size / sizeof(Elf64_Dyn); ++i)
    {
        if (dyn_entries[i].d_tag == DT_NEEDED)
        {
            lib_dep->lib_dep_names = realloc(lib_dep->lib_dep_names,
                (lib_dep->lib_dep_count + 1) * sizeof(char *));
            lib_dep->lib_dep_names[lib_dep->lib_dep_count]
                = malloc(strlen(&dynstr_tbl[dyn_entries[i].d_un.d_val]));
            strcpy(lib_dep->lib_dep_names[lib_dep->lib_dep_count],
                &dynstr_tbl[dyn_entries[i].d_un.d_val]);
            lib_dep->lib_dep_count += 1;
        }
    }

    free(dynstr_tbl);
    free(dyn_entries);
}

static void
find_comp_entry_points(
    char **entry_points, size_t entry_point_count, struct Compartment *new_comp)
{
    new_comp->entry_points
        = malloc(entry_point_count * sizeof(struct CompEntryPoint));
    for (size_t i = 0; i < entry_point_count; ++i)
    {
        struct LibSymSearchResult found_sym
            = find_lib_dep_sym_in_comp(entry_points[i], new_comp);
        if (found_sym.lib_idx == USHRT_MAX)
        {
            errx(1, "Did not find entry point %s!\n", entry_points[i]);
        }
        struct CompEntryPoint new_entry_point
            = { entry_points[i], extract_sym_offset(new_comp, found_sym) };
        new_comp->entry_points[new_comp->entry_point_count] = new_entry_point;
        new_comp->entry_point_count += 1;
    }
}

static void
find_comp_intercepts(char **intercepts, void **intercept_addrs,
    size_t intercept_count, struct Compartment *new_comp)
{
    // Find symbols for intercepts
    char **intercept_names = malloc(intercept_count * sizeof(char *));
    const char *so_plt_suffix = "@plt";
    for (size_t i = 0; i < intercept_count; ++i)
    {
        size_t to_intercept_name_len
            = strlen(intercepts[i]) + strlen(so_plt_suffix) + 1;
        intercept_names[i] = malloc(to_intercept_name_len);
        strcpy(intercept_names[i], intercepts[i]);
        strcat(intercept_names[i], so_plt_suffix);
    }
    for (size_t i = 0; i < intercept_count; ++i)
    {
        struct LibSymSearchResult found_sym
            = find_lib_dep_sym_in_comp(intercept_names[i], new_comp);
        if (found_sym.lib_idx == USHRT_MAX)
        {
            continue;
        }

        // TODO double check
        comp_add_intercept(new_comp,
            (uintptr_t) extract_sym_offset(new_comp, found_sym),
            (uintptr_t) intercept_addrs[i]);
        free(intercept_names[i]);
    }
    free(intercept_names);
}

static void
resolve_rela_syms(struct Compartment *new_comp)
{
    // Find all symbols for eager relocation mapping
    for (size_t i = 0; i < new_comp->libs_count; ++i)
    {
        for (size_t j = 0; j < new_comp->libs[i]->rela_maps_count; ++j)
        {
            // Ignore relocations we don't want to load, as earlier set on
            // lookup (e.g., weak-bound symbols)
            if (new_comp->libs[i]->rela_maps[j].rela_address == 0)
            {
                continue;
            }

            struct LibSymSearchResult found_sym = find_lib_dep_sym_in_comp(
                new_comp->libs[i]->rela_maps[j].rela_name, new_comp);
            if (found_sym.lib_idx == USHRT_MAX)
            {
                errx(1, "Did not find symbol %s!\n",
                    new_comp->libs[i]->rela_maps[j].rela_name);
            }
            new_comp->libs[i]->rela_maps[j].target_func_address
                = extract_sym_offset(new_comp, found_sym);
        }
    }
}

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

static ssize_t
do_pread(int fd, void *buf, size_t count, off_t offset)
{
    ssize_t res = pread(fd, buf, count, offset);
    if (res == -1)
    {
        err(1, "Error in pread");
    }
    return res;
}

static void
get_lib_name(struct LibDependency *lib_dep, const char *lib_path)
{
    const char *basename = strrchr(lib_path, '/') + 1;
    lib_dep->lib_name = malloc(strlen(basename));
    strcpy(lib_dep->lib_name, basename);
}

static void *
extract_sym_offset(struct Compartment *comp, struct LibSymSearchResult res)
{
    return (char *) comp->libs[res.lib_idx]->lib_mem_base
        + (intptr_t) comp->libs[res.lib_idx]->lib_syms[res.sym_idx].sym_offset;
}

static struct LibSymSearchResult
find_lib_dep_sym_in_comp(
    const char *to_find, struct Compartment *comp_to_search)
{
    for (size_t i = 0; i < comp_to_search->libs_count; ++i)
    {
        for (size_t j = 0; j < comp_to_search->libs[i]->lib_syms_count; ++j)
        {
            if (!strcmp(to_find, comp_to_search->libs[i]->lib_syms[j].sym_name))
            {
                struct LibSymSearchResult res = { i, j };
                return res;
            }
        }
    }
    struct LibSymSearchResult res = { -1, -1 };
    return res;
}

static char *
find_in_dir(const char *const lib_name, char *search_dir)
{
    assert(search_dir != NULL);
    char **search_paths = malloc(2 * sizeof(char *));
    search_paths[0] = search_dir;
    search_paths[1] = NULL;
    FTS *dir = fts_open(search_paths, FTS_LOGICAL, NULL);
    if (!dir)
    {
        err(1, "Failed fts_open for path %s.\n", search_dir);
    }

    FTSENT *curr_entry;
    while ((curr_entry = fts_read(dir)) != NULL)
    {
        if (!strcmp(lib_name, curr_entry->fts_name))
        {
            break;
        }
    }
    fts_close(dir);
    free(search_paths);
    if (curr_entry != NULL)
    {
        return curr_entry->fts_path;
    }
    return NULL;
}

// TODO carefully recheck all the numbers are right
static void
init_comp_scratch_mem(struct Compartment *new_comp)
{
    new_comp->scratch_mem_base = align_up(
        (char *) new_comp->base + new_comp->size + new_comp->page_size,
        new_comp->page_size);
    new_comp->max_manager_caps_count = 10; // TODO
    new_comp->scratch_mem_heap_size = 0x800000UL; // TODO
    new_comp->scratch_mem_size = new_comp->scratch_mem_heap_size
        + new_comp->max_manager_caps_count * sizeof(void *__capability)
        + new_comp->mng_trans_fn_sz;
    new_comp->scratch_mem_alloc = 0;
    new_comp->scratch_mem_stack_top = align_down(
        (char *) new_comp->scratch_mem_base + new_comp->scratch_mem_heap_size,
        16);
    new_comp->scratch_mem_stack_size = 0x80000UL; // TODO
    new_comp->manager_caps = new_comp->scratch_mem_stack_top;
    new_comp->active_manager_caps_count = 0;
    new_comp->mng_trans_fn = (char *) new_comp->manager_caps
        + new_comp->max_manager_caps_count * sizeof(void *__capability);

    assert(((uintptr_t) new_comp->scratch_mem_base) % 16 == 0);
    assert(
        (((uintptr_t) new_comp->scratch_mem_base) + new_comp->scratch_mem_size)
            % 16
        == 0);
    assert(((uintptr_t) new_comp->scratch_mem_stack_top) % 16 == 0);
    assert((((uintptr_t) new_comp->scratch_mem_stack_top)
               - new_comp->scratch_mem_stack_size)
            % 16
        == 0);
    assert(new_comp->scratch_mem_size % 16 == 0);
}

/*******************************************************************************
 * Print functions
 ******************************************************************************/
static void
print_lib_dep_seg(struct SegmentMap *lib_dep_seg)
{
    printf(">> bot %p // top %p // off 0x%zx // corr 0x%zx // msz 0x%zx // fsz "
           "0x%zx\n",
        lib_dep_seg->mem_bot, lib_dep_seg->mem_top, lib_dep_seg->offset,
        lib_dep_seg->correction, lib_dep_seg->mem_sz, lib_dep_seg->file_sz);
}

static void
print_lib_dep(struct LibDependency *lib_dep)
{
    printf("== LIB DEPENDENCY\n");
    printf("- lib_name : %s\n", lib_dep->lib_name);
    printf("- lib_path : %s\n", lib_dep->lib_path);
    printf("- lib_mem_base : %p\n", lib_dep->lib_mem_base);

    printf("- lib_segs_count : %lu\n", lib_dep->lib_segs_count);
    printf("- lib_segs_size : 0x%zx\n", lib_dep->lib_segs_size);
    for (size_t i = 0; i < lib_dep->lib_segs_count; ++i)
    {
        printf("\t");
        print_lib_dep_seg(&lib_dep->lib_segs[i]);
    }

    printf("- lib_syms_count : %lu\n", lib_dep->lib_syms_count);

    printf("- lib_dep_count : %hu\n", lib_dep->lib_dep_count);
    printf("- lib_dep_names :\n");
    for (size_t i = 0; i < lib_dep->lib_dep_count; ++i)
    {
        printf("--- %s\n", lib_dep->lib_dep_names[i]);
    }

    printf("- rela_maps_count : %zu\n", lib_dep->rela_maps_count);
    printf("== DONE\n");
}
