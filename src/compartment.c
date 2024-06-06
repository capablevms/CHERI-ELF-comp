#include "compartment.h"

const char *libs_path_env_var = "COMP_LIBRARY_PATH";
const char *tls_rtld_dropin = "tls_lookup_stub";
const char *comp_utils_soname = "libcomputils.so";

/*******************************************************************************
 * Forward declarations
 ******************************************************************************/

static struct LibDependency *
parse_lib_file(char *, struct Compartment *);
static void
parse_lib_segs(Elf64_Ehdr *, int, struct LibDependency *, struct Compartment *);
static void
parse_lib_symtb(Elf64_Shdr *, Elf64_Ehdr *, int, struct LibDependency *);
static void
parse_lib_rela(Elf64_Shdr *, Elf64_Ehdr *, int, struct LibDependency *);
static void
parse_lib_dynamic_deps(Elf64_Shdr *, Elf64_Ehdr *, int, struct LibDependency *);
static void
find_comp_entry_points(char **, size_t, struct Compartment *);
static void
resolve_rela_syms(struct Compartment *);
static struct LibSymSearchResult
find_lib_dep_sym_in_comp(const char *, struct Compartment *, unsigned short);
static void *
extract_sym_offset(struct Compartment *, struct LibSymSearchResult);

static ssize_t
do_pread(int, void *, size_t, off_t);
static char *
find_in_dir(const char *, char *);
static void
init_comp_scratch_mem(struct Compartment *);
static void
resolve_comp_tls_regions(struct Compartment *);

static void
print_lib_dep_seg(struct SegmentMap *);
static void
print_lib_dep(struct LibDependency *);
static void
print_comp(struct Compartment *);

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

    new_comp->scratch_mem_heap_size = 0;
    new_comp->scratch_mem_stack_top = NULL;
    new_comp->scratch_mem_stack_size = 0;

    new_comp->libs_count = 0;
    new_comp->libs = NULL;
    new_comp->entry_point_count = 0;
    new_comp->entry_points = NULL;
    new_comp->libs_tls_sects = NULL;

    new_comp->page_size = sysconf(_SC_PAGESIZE);

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

        // Get `tls_lookup_func` if we parsed `comp_utils.so`
        if (!strcmp(parsed_lib->lib_name, comp_utils_soname))
        {
            for (size_t i = 0; i < parsed_lib->lib_syms_count; ++i)
            {
                if (!strcmp(parsed_lib->lib_syms[i].sym_name, tls_rtld_dropin))
                {
                    new_comp->tls_lookup_func
                        = (char *) parsed_lib->lib_syms[i].sym_offset
                        + (intptr_t) parsed_lib->lib_mem_base;
                    break;
                }
            }
            assert(new_comp->tls_lookup_func);
        }

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
    find_comp_entry_points(entry_points, entry_point_count, new_comp);
    resolve_rela_syms(new_comp);
    resolve_comp_tls_regions(new_comp);

    // Compartment size sanity check
    assert(new_comp->mem_top
        == (char *) new_comp->base + // base compartment address
            new_comp->size + // size of loaded ELF files
            new_comp->page_size
            + // buffer between scratch memory and compartment libraries
            new_comp->scratch_mem_size // size of scratch memory
    );

    return new_comp;
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
                err(1, "Error mapping library %s dependency segment idx %zu",
                    lib_dep->lib_name, j);
            }
            do_pread(lib_dep_fd,
                (char *) lib_dep->lib_mem_base
                    + (uintptr_t) lib_dep_seg.mem_bot,
                lib_dep_seg.file_sz, lib_dep_seg.offset);
        }
        close(lib_dep_fd);
    }

    // Map compartment scratch memory - heap, stack, sealed manager
    // capabilities for transition out, capabilities to call other compartments
    // (TODO fix this), TLS region (if applicable)
    map_result
        = mmap((void *) to_map->scratch_mem_base, to_map->scratch_mem_size,
            PROT_READ | PROT_WRITE, // | PROT_EXEC, // TODO Fix this
            MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (map_result == MAP_FAILED)
    {
        err(1, "Error mapping compartment %zu scratch memory", to_map->id);
    }

    size_t tls_allocd = 0x0;
    for (size_t i = 0; i < to_map->libs_count; ++i)
    {
        // Bind `.got.plt` entries
        for (size_t j = 0; j < to_map->libs[i]->rela_maps_count; ++j)
        {
            assert(to_map->libs[i]->rela_maps[j].rela_address != 0);
            if (to_map->libs[i]->rela_maps[j].target_func_address == 0)
            {
                continue;
            }
            memcpy(to_map->libs[i]->rela_maps[j].rela_address,
                &to_map->libs[i]->rela_maps[j].target_func_address,
                sizeof(void *));
        }

        // Map .tdata sections
        if (to_map->libs[i]->tls_data_size != 0)
        {
            assert(to_map->libs[i]->tls_sec_addr);
            memcpy((char *) to_map->libs_tls_sects->region_start + tls_allocd,
                to_map->libs[i]->tls_sec_addr, to_map->libs[i]->tls_data_size);
            tls_allocd += to_map->libs[i]->tls_sec_size;
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
    // TODO
    // * set TPIDR_EL0 to TLS start, if given
    // * make `tls_lookup_stub` get the index
    // * fix statics?
    result = comp_exec_in(to_exec->scratch_mem_stack_top, to_exec->ddc, fn,
        args, args_count, sealed_redirect_cap,
        to_exec->libs_tls_sects->region_start);
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
            if (curr_lib_dep->rela_maps[j].rela_name)
            {
                free(curr_lib_dep->rela_maps[j].rela_name);
            }
        }
        free(curr_lib_dep->rela_maps);

        free(curr_lib_dep->lib_name);
        free(curr_lib_dep->lib_path);
        free(curr_lib_dep);
    }
    free(to_clean->libs);
    free(to_clean->entry_points);
    if (to_clean->libs_tls_sects)
    {
        free(to_clean->libs_tls_sects->lib_idxs);
        free(to_clean->libs_tls_sects);
    }
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
            errx(1, "Error opening compartment file  %s!\n", lib_name);
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
    new_lib->lib_name = malloc(strlen(lib_name) + 1);
    strcpy(new_lib->lib_name, lib_name);
    if (lib_path)
    {
        new_lib->lib_path = malloc(strlen(lib_path) + 1);
        strcpy(new_lib->lib_path, lib_path);
    }
    else
    {
        new_lib->lib_path = malloc(strlen(lib_name) + 1);
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

    new_lib->tls_sec_addr = 0x0;
    new_lib->tls_sec_size = 0;
    new_lib->tls_data_size = 0;

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
    // Therefore, we expect each `if` to be only entered once. However, we note
    // that this can be changed in future specifications.
    //
    // Source: https://refspecs.linuxfoundation.org/elf/elf.pdf
    const size_t headers_of_interest_count = 4;
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
            parse_lib_rela(&curr_shdr, &lib_ehdr, lib_fd, new_lib);
            found_headers += 1;
        }
        else if (curr_shdr.sh_type == SHT_RELA
            && !strcmp(&shstrtab[curr_shdr.sh_name], ".rela.dyn"))
        {
            parse_lib_rela(&curr_shdr, &lib_ehdr, lib_fd, new_lib);
            found_headers += 1;
        }
        // Lookup `.dynamic` to find library dependencies
        else if (curr_shdr.sh_type == SHT_DYNAMIC)
        {
            parse_lib_dynamic_deps(&curr_shdr, &lib_ehdr, lib_fd, new_lib);
            found_headers += 1;
        }
        // Section containing TLS static data
        else if (curr_shdr.sh_type == SHT_PROGBITS
            && curr_shdr.sh_flags & SHF_TLS)
        {
            assert(new_lib->tls_sec_addr);
            new_lib->tls_data_size = curr_shdr.sh_size;
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

        if (lib_phdr.p_type == PT_TLS)
        {
            if (!new_comp->libs_tls_sects)
            {
                new_comp->libs_tls_sects = malloc(sizeof(struct TLSDesc));
            }
            lib_dep->tls_sec_addr = (void *) lib_phdr.p_vaddr;
            lib_dep->tls_sec_size = lib_phdr.p_memsz;
        }

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
    if (lib_dep->tls_sec_addr)
    {
        lib_dep->tls_sec_addr = (char *) lib_dep->tls_sec_addr
            + (uintptr_t) lib_dep->lib_mem_base;
    }
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
        // TODO currently ignore symbols of unspecified type
        if (ELF_ST_TYPE(curr_sym.st_info) == STT_NOTYPE)
        {
            continue;
        }

        ld_syms[actual_syms].sym_offset = (void *) curr_sym.st_value;
        char *sym_name = &str_tb[curr_sym.st_name];
        ld_syms[actual_syms].sym_name = malloc(strlen(sym_name) + 1);
        strcpy(ld_syms[actual_syms].sym_name, sym_name);
        ld_syms[actual_syms].sym_type = ELF64_ST_TYPE(curr_sym.st_info);
        ld_syms[actual_syms].sym_bind = ELF64_ST_BIND(curr_sym.st_info);
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
parse_lib_rela(Elf64_Shdr *rela_shdr, Elf64_Ehdr *lib_ehdr, int lib_fd,
    struct LibDependency *lib_dep)
{
    // Traverse `.rela.plt`, so we can see which function addresses we need
    // to eagerly load
    Elf64_Rela *rela_sec = malloc(rela_shdr->sh_size);
    do_pread(lib_fd, rela_sec, rela_shdr->sh_size, rela_shdr->sh_offset);
    size_t rela_count = rela_shdr->sh_size / sizeof(Elf64_Rela);

    Elf64_Shdr dyn_sym_hdr;
    do_pread(lib_fd, &dyn_sym_hdr, sizeof(Elf64_Shdr),
        lib_ehdr->e_shoff + rela_shdr->sh_link * sizeof(Elf64_Shdr));
    Elf64_Sym *dyn_sym_tbl = malloc(dyn_sym_hdr.sh_size);
    do_pread(lib_fd, dyn_sym_tbl, dyn_sym_hdr.sh_size, dyn_sym_hdr.sh_offset);

    Elf64_Shdr dyn_str_hdr;
    do_pread(lib_fd, &dyn_str_hdr, sizeof(Elf64_Shdr),
        lib_ehdr->e_shoff + dyn_sym_hdr.sh_link * sizeof(Elf64_Shdr));
    char *dyn_str_tbl = malloc(dyn_str_hdr.sh_size);
    do_pread(lib_fd, dyn_str_tbl, dyn_str_hdr.sh_size, dyn_str_hdr.sh_offset);

    // XXX Since TLSDESC entries might resolve to two relocation slots, we
    // ensure we have enough space by doubling the expected relocation counts
    struct LibRelaMapping *new_relas
        = malloc(2 * rela_count * sizeof(struct LibRelaMapping));

    // Prepare TLS look-up function relocation (will be copied for each TLS
    // relocation entry
    static struct LibRelaMapping tls_lrm
        = { NULL, 0x0, 0x0, -1, STT_FUNC, STB_GLOBAL };

    // Log symbols that will need to be relocated eagerly at maptime
    Elf64_Rela curr_rela;
    size_t actual_relas = 0;
    for (size_t j = 0; j < rela_count; ++j)
    {
        curr_rela = rela_sec[j];
        size_t curr_rela_sym_idx = ELF64_R_SYM(curr_rela.r_info);
        size_t curr_rela_type = ELF64_R_TYPE(curr_rela.r_info);

        struct LibRelaMapping lrm = { NULL, 0x0, 0x0, curr_rela_type, -1, -1 };

        // XXX We handle `TLS` symbols differently. It seems the way
        // AARCH64 handles TLS variables is preferentially via
        // `R_AARCH64_TLSDESC` entries, or more commonly known as TLS
        // descriptors. We will focus on "General Dynamic" model. For this,
        // each TLS variable relocates **two** slots in the GOT - the first
        // is the address of a function to do the TLS lookup, usually
        // against a data structure containing all TLS info, and the second
        // is the parameter passed to that function. We will use our own
        // function in `comp_utils` to do the lookup, `tls_rtld_dropin`,
        // and simplify the process slightly by just recording the eagerly
        // relocated address of the TLS variables (NB we enforce the number
        // of threads, if different than one, is known at map time, so we
        // don't need to dynamically handle TLS regions)
        //
        // Sources:
        // * Speeding Up Thread-Local Storage Access in Dynamic Libraries
        // in the ARM platform
        // [https://www.fsfla.org/~lxoliva/writeups/TLS/paper-lk2006.pdf]
        // * ELF for the Arm® 64-bit Architecture (AArch64) - 2023Q3
        // [https://github.com/ARM-software/abi-aa/releases/download/2023Q3/aaelf64.pdf]
        // * All about thread-local storage
        // [https://maskray.me/blog/2021-02-14-all-about-thread-local-storage]
        // * ELF Handling For Thread-Local Storage
        // [https://www.akkadia.org/drepper/tls.pdf]
        // A Deep dive into (implicit) Thread Local Storage
        // [https://chao-tic.github.io/blog/2018/12/25/tls]
        //
        // TODO probably more types?
        if (curr_rela_type == R_AARCH64_TLSDESC)
        {
            // Add relocation entry for TLS lookup function
            memcpy(new_relas + actual_relas, &tls_lrm,
                sizeof(struct LibRelaMapping));
            new_relas[actual_relas].rela_name
                = malloc(strlen(tls_rtld_dropin) + 1);
            strcpy(new_relas[actual_relas].rela_name, tls_rtld_dropin);
            new_relas[actual_relas].rela_address
                = curr_rela.r_offset + (char *) lib_dep->lib_mem_base;
            actual_relas += 1;

            // Add relocation entry for actual TLS variable
            if (curr_rela_sym_idx == 0)
            {
                lrm.rela_sym_type = STT_TLS;
                lrm.rela_sym_bind = STB_GLOBAL; // TODO help
                lrm.target_func_address = (void *) curr_rela.r_addend;
            }
            else
            {
                Elf64_Sym curr_rela_sym = dyn_sym_tbl[curr_rela_sym_idx];
                lrm.rela_sym_type = ELF64_ST_TYPE(curr_rela_sym.st_info);
                lrm.rela_sym_bind = ELF64_ST_BIND(curr_rela_sym.st_info);
                lrm.target_func_address = (void *) curr_rela_sym.st_value;
            }

            // Offset relocation address by one slot, due to the lookup
            // function relocation
            lrm.rela_address = curr_rela.r_offset
                + (char *) lib_dep->lib_mem_base + sizeof(void *);
        }
        else if (curr_rela_type == R_AARCH64_TLS_TPREL64)
        {
            lrm.target_func_address = (char *) curr_rela.r_addend;
            lrm.rela_address
                = curr_rela.r_offset + (char *) lib_dep->lib_mem_base;
        }
        else
        {
            // Relocation entry refers to raw addresses, not a symbol entry
            if (curr_rela_sym_idx == 0)
            {
                lrm.target_func_address
                    = curr_rela.r_addend + (char *) lib_dep->lib_mem_base;
            }
            // Relocation entry refers to a symbol entry
            else
            {
                Elf64_Sym curr_rela_sym = dyn_sym_tbl[curr_rela_sym_idx];

                // Filter out some `libc` symbols we don't want to handle
                // TODO at least right now
                if (!strcmp(&dyn_str_tbl[curr_rela_sym.st_name], "environ"))
                {
                    warnx("Currently not relocating symbol `environ` from "
                          "library "
                          "%s - "
                          "using within a container might cause a crash.",
                        lib_dep->lib_name);
                    continue;
                }
                else if (!strcmp(
                             &dyn_str_tbl[curr_rela_sym.st_name], "__progname"))
                {
                    warnx("Currently not relocating symbol `__progname` from "
                          "library %s "
                          "- using within a container might cause a crash.",
                        lib_dep->lib_name);
                    continue;
                }

                lrm.rela_name
                    = malloc(strlen(&dyn_str_tbl[curr_rela_sym.st_name]) + 1);
                strcpy(lrm.rela_name, &dyn_str_tbl[curr_rela_sym.st_name]);
                lrm.rela_sym_type = ELF64_ST_TYPE(curr_rela_sym.st_info);
                lrm.rela_sym_bind = ELF64_ST_BIND(curr_rela_sym.st_info);
                if (curr_rela_sym.st_value != 0
                    && lrm.rela_sym_bind != STB_WEAK)
                {
                    lrm.target_func_address = curr_rela_sym.st_value
                        + (char *) lib_dep->lib_mem_base;
                }

                // TODO
                assert(curr_rela.r_addend == 0
                    && "I want to check if we have symbol-related relocations "
                       "with "
                       "addends");
            }
            lrm.rela_address
                = curr_rela.r_offset + (char *) lib_dep->lib_mem_base;
        }
        memcpy(new_relas + actual_relas, &lrm, sizeof(struct LibRelaMapping));
        actual_relas += 1;
    }
    lib_dep->rela_maps = realloc(lib_dep->rela_maps,
        (lib_dep->rela_maps_count + actual_relas)
            * sizeof(struct LibRelaMapping));
    memcpy(&lib_dep->rela_maps[lib_dep->rela_maps_count], new_relas,
        actual_relas * sizeof(struct LibRelaMapping));
    lib_dep->rela_maps_count += actual_relas;

    free(new_relas);
    free(rela_sec);
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
                = malloc(strlen(&dynstr_tbl[dyn_entries[i].d_un.d_val]) + 1);
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
            = find_lib_dep_sym_in_comp(entry_points[i], new_comp, STT_FUNC);
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
resolve_rela_syms(struct Compartment *new_comp)
{
    // Find all symbols for eager relocation mapping
    size_t prev_tls_secs_size = 0;
    for (size_t i = 0; i < new_comp->libs_count; ++i)
    {
        for (size_t j = 0; j < new_comp->libs[i]->rela_maps_count; ++j)
        {
            struct LibRelaMapping *curr_rela_map
                = &new_comp->libs[i]->rela_maps[j];

            if (curr_rela_map->rela_sym_type == STT_TLS)
            {
                curr_rela_map->target_func_address
                    = (char *) curr_rela_map->target_func_address
                    + prev_tls_secs_size;
                continue;
            }

            if (curr_rela_map->target_func_address != 0
                || curr_rela_map->rela_type == R_AARCH64_TLS_TPREL64)
            {
                continue;
            }

            if (curr_rela_map->rela_name
                && !strcmp(curr_rela_map->rela_name, tls_rtld_dropin))
            {
                curr_rela_map->target_func_address = new_comp->tls_lookup_func;
                continue;
            }

            struct LibSymSearchResult found_sym
                = find_lib_dep_sym_in_comp(curr_rela_map->rela_name, new_comp,
                    curr_rela_map->rela_sym_type);
            if (found_sym.lib_idx == USHRT_MAX)
            {
                if (curr_rela_map->rela_sym_bind == STB_WEAK)
                {
                    warnx("Did not find WEAK symbol %s of type %hu (idx %zu in "
                          "library %s (idx %zu)) - execution *might* fault.",
                        curr_rela_map->rela_name, curr_rela_map->rela_sym_type,
                        j, new_comp->libs[i]->lib_name, i);
                    continue;
                }
                else
                {
                    errx(1,
                        "Did not find symbol %s of type %hu (idx %zu in "
                        "library %s "
                        "(idx %zu))!",
                        curr_rela_map->rela_name, curr_rela_map->rela_sym_type,
                        j, new_comp->libs[i]->lib_name, i);
                }
            }
            curr_rela_map->target_func_address
                = extract_sym_offset(new_comp, found_sym);
        }
        prev_tls_secs_size += new_comp->libs[i]->tls_sec_size;
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

static void *
extract_sym_offset(struct Compartment *comp, struct LibSymSearchResult res)
{
    return (char *) comp->libs[res.lib_idx]->lib_mem_base
        + (intptr_t) comp->libs[res.lib_idx]->lib_syms[res.sym_idx].sym_offset;
}

static struct LibSymSearchResult
find_lib_dep_sym_in_comp(const char *to_find,
    struct Compartment *comp_to_search, const unsigned short sym_type)
{
    for (size_t i = 0; i < comp_to_search->libs_count; ++i)
    {
        for (size_t j = 0; j < comp_to_search->libs[i]->lib_syms_count; ++j)
        {
            // Ignore non-symbol relocations
            if (!comp_to_search->libs[i]->lib_syms[j].sym_name)
            {
                continue;
            }

            // TODO eyeball performance of this approach versus using `&&`
            // Ignore `LOCAL` bind symbols - they cannot be relocated against
            bool cond
                = comp_to_search->libs[i]->lib_syms[j].sym_bind != STB_LOCAL;

            // Check symbol name matches
            cond = cond
                && !strcmp(
                    to_find, comp_to_search->libs[i]->lib_syms[j].sym_name);

            // Check symbol type matches
            cond = cond
                && comp_to_search->libs[i]->lib_syms[j].sym_type == sym_type;

            // Symbols cannot have 0-offset values
            if (sym_type != STT_TLS)
            {
                cond = cond
                    && comp_to_search->libs[i]->lib_syms[j].sym_offset != 0;
            }

            if (cond)
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
    new_comp->scratch_mem_heap_size = 0x800000UL; // TODO
    new_comp->scratch_mem_stack_size = 0x80000UL; // TODO
    new_comp->scratch_mem_stack_top = align_down(
        (char *) new_comp->scratch_mem_base + new_comp->scratch_mem_heap_size,
        16);

    new_comp->scratch_mem_size
        = new_comp->scratch_mem_heap_size + new_comp->scratch_mem_stack_size;

    new_comp->mem_top = (char *) new_comp->mem_top
        + ((char *) new_comp->scratch_mem_base - (char *) new_comp->mem_top)
        + new_comp->scratch_mem_size;

    assert((uintptr_t) new_comp->scratch_mem_base % new_comp->page_size == 0);
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

static void
resolve_comp_tls_regions(struct Compartment *new_comp)
{
    if (!new_comp->libs_tls_sects)
    {
        return;
    }
    assert(new_comp->tls_lookup_func);

    // TODO currently we only support one thread
    new_comp->libs_tls_sects->region_count = 1;
    new_comp->libs_tls_sects->region_start = new_comp->scratch_mem_stack_top;
    new_comp->libs_tls_sects->libs_count = 0;

    unsigned short *lib_idxs
        = malloc(new_comp->libs_count * sizeof(unsigned short));
    unsigned short actual_idxs = 0;
    size_t comp_tls_size = 0;
    for (size_t i = 0; i < new_comp->libs_count; ++i)
    {
        if (new_comp->libs[i]->tls_sec_addr == 0x0)
        {
            continue;
        }
        comp_tls_size += new_comp->libs[i]->tls_sec_size;
        new_comp->libs_tls_sects->libs_count += 1;

        lib_idxs[actual_idxs] = i;
        actual_idxs += 1;
    }
    comp_tls_size = align_up(comp_tls_size, 16);
    lib_idxs = realloc(lib_idxs,
        new_comp->libs_tls_sects->libs_count * sizeof(unsigned short));
    new_comp->libs_tls_sects->lib_idxs = lib_idxs;

    intptr_t total_tls_size
        = comp_tls_size * new_comp->libs_tls_sects->region_count;
    new_comp->scratch_mem_size += total_tls_size;
    new_comp->mem_top = (char *) new_comp->mem_top + total_tls_size;
    new_comp->libs_tls_sects->region_size = comp_tls_size;

    assert((uintptr_t) new_comp->libs_tls_sects->region_start % 16 == 0);
    // TODO reconsider scratch memory layout
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

static void
print_comp(struct Compartment *to_print)
{
    printf("== COMPARTMENT\n");
    printf("- id : %lu\n", to_print->id);
    {
        printf("- DDC : ");
        printf(" base - 0x%lx ", cheri_base_get(to_print->ddc));
        printf(" length - 0x%lx ", cheri_length_get(to_print->ddc));
        printf(" address - 0x%lx ", cheri_address_get(to_print->ddc));
        printf(" offset - 0x%lx ", cheri_offset_get(to_print->ddc));
        printf("\n");
    }
    printf("- size : 0x%zx\n", to_print->size);
    printf("- base : %p\n", to_print->base);
    printf("- mem_top : %p\n", to_print->mem_top);
    printf("- mapped : %s\n", to_print->mapped ? "true" : "false");

    printf("- scratch_mem_base : %p\n", to_print->scratch_mem_base);
    printf("- scratch_mem_size : 0x%zx", to_print->scratch_mem_size);
    printf(" [0x%zx heap + 0x%zx stack + 0x%zx tls]\n",
        to_print->scratch_mem_heap_size, to_print->scratch_mem_stack_size,
        to_print->libs_tls_sects->region_size
            * to_print->libs_tls_sects->region_count);
    printf(
        "- scratch_mem_heap_size : 0x%zx\n", to_print->scratch_mem_heap_size);
    printf("- scratch_mem_stack_top : %p\n", to_print->scratch_mem_stack_top);
    printf(
        "- scratch_mem_stack_size : 0x%zx\n", to_print->scratch_mem_stack_size);

    printf("- libs_count : %lu\n", to_print->libs_count);
    printf("- entry_point_count : %lu\n", to_print->entry_point_count);
    // TODO entry_points
    printf("- tld_lookup_func : %p\n", to_print->tls_lookup_func);
    printf("- libs_tls_sects :\n");
    printf("\t> region_count : %hu\n", to_print->libs_tls_sects->region_count);
    printf("\t> region_size : 0x%zx\n", to_print->libs_tls_sects->region_size);
    // TODO region_start
    printf("\t> region_start : %p\n", to_print->libs_tls_sects->region_start);
    printf("\t> libs_count : %hu\n", to_print->libs_tls_sects->libs_count);
    printf("\t> libs_idxs : ");
    for (unsigned short i = 0; i < to_print->libs_tls_sects->libs_count; ++i)
    {
        printf("%hu,", to_print->libs_tls_sects->lib_idxs[i]);
    }
    printf("\n");

    printf("- page_size : %lu\n", to_print->page_size);

    printf("== DONE\n");
}
