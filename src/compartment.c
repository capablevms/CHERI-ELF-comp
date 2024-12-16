#include "compartment.h"

const char *libs_path_env_var = "COMP_LIBRARY_PATH";
const char *tls_rtld_dropin = "tls_lookup_stub";
const char *comp_utils_soname = "libcomputils.so";

/*******************************************************************************
 * Forward declarations
 ******************************************************************************/

static struct Compartment *
comp_init();
static struct LibDependency *
lib_init();

static struct LibDependency *
parse_lib_file(char *, struct Compartment *);
static void
parse_lib_segs(
    Elf64_Ehdr *, void *, struct LibDependency *, struct Compartment *);
static void
parse_lib_symtb(Elf64_Shdr *, Elf64_Ehdr *, void *, struct LibDependency *);
static void
parse_lib_rela(Elf64_Shdr *, Elf64_Ehdr *, void *, struct LibDependency *);
static void
parse_lib_dynamic_deps(
    Elf64_Shdr *, Elf64_Ehdr *, void *, struct LibDependency *);
static void
map_comp_entry_points(struct Compartment *);
static void
resolve_rela_syms(struct Compartment *);
static void
find_tls_lookup_func(struct Compartment *);

static bool
check_lib_dep_sym(lib_symbol *, const unsigned short);
static void *
eval_staged_sym_offset(struct Compartment *, const comp_symbol *);
static void *
eval_staged_sym_tls_offset(struct Compartment *, const comp_symbol *);
static void *
eval_sym_offset(struct Compartment *, const comp_symbol *);
static void *
eval_lib_sym_offset(struct Compartment *, const size_t, const lib_symbol *);

static void
get_lib_data(void *, void *, size_t, off_t);
static void *
seek_lib_data(void *, off_t);
static char *
find_in_dir(const char *, char *);
static void
init_comp_scratch_mem(struct Compartment *);
static void
adjust_comp_scratch_mem(struct Compartment *, size_t);
static inline void *
get_extra_scratch_region_base(struct Compartment *);
static void
setup_environ(struct Compartment *);
static void
resolve_comp_tls_regions(struct Compartment *);
static void
stage_comp(struct Compartment *);

static void
print_lib_dep_seg(struct SegmentMap *);
static void
print_lib_dep(struct LibDependency *);
static void
print_comp_simple(struct Compartment *);

/*******************************************************************************
 * Main compartment functions
 ******************************************************************************/

/* Initialize some values of the Compartment struct. The rest are expected to
 * be set in `comp_from_elf`.
 */
static struct Compartment *
comp_init()
{
    // TODO order
    struct Compartment *new_comp = malloc(sizeof(struct Compartment));

    new_comp->total_size = 0;
    new_comp->data_size = 0;
    new_comp->staged_addr = NULL;

    new_comp->scratch_mem_base = NULL;
    new_comp->scratch_mem_size = 0;

    new_comp->scratch_mem_heap_size = 0;
    new_comp->scratch_mem_stack_top = NULL;
    new_comp->scratch_mem_stack_size = 0;
    new_comp->scratch_mem_extra = 0;

    new_comp->libs_count = 0;
    new_comp->libs = NULL;
    new_comp->libs_tls_sects = NULL;
    new_comp->comp_syms = comp_syms_init();

    new_comp->page_size = sysconf(_SC_PAGESIZE);

    return new_comp;
}

static struct LibDependency *
lib_init()
{
    struct LibDependency *new_lib = malloc(sizeof(struct LibDependency));

    new_lib->lib_name = NULL;
    new_lib->lib_path = NULL;
    new_lib->lib_mem_base = 0x0;

    new_lib->lib_segs_count = 0;
    new_lib->lib_segs_size = 0;
    new_lib->lib_segs = NULL;

    new_lib->lib_syms = NULL;

    new_lib->lib_dep_count = 0;
    new_lib->lib_dep_names = NULL;

    new_lib->rela_maps_count = 0;
    new_lib->rela_maps = NULL;

    new_lib->tls_sec_addr = 0x0;
    new_lib->tls_sec_off = 0;
    new_lib->tls_sec_size = 0;
    new_lib->tls_data_size = 0;
    new_lib->tls_offset = 0;

    return new_lib;
}

/* Give a binary ELF file in `filename`, read the ELF data and store it within
 * a `struct Compartment`. At this point, we only read data.
 */
struct Compartment *
comp_from_elf(char *filename, struct CompConfig *cc)
{
    struct Compartment *new_comp = comp_init();
    new_comp->cc = cc;

    unsigned short libs_to_parse_count = 1;
    unsigned short libs_parsed_count = 0;
    char **libs_to_parse = malloc(sizeof(char *));
    libs_to_parse[0] = filename;

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

    assert(cc->entry_points);
    assert(cc->entry_point_count > 0);
    new_comp->total_size += align_up(
        new_comp->data_size + new_comp->page_size, new_comp->page_size);

    init_comp_scratch_mem(new_comp);
    setup_environ(new_comp);
    map_comp_entry_points(new_comp);
    resolve_comp_tls_regions(new_comp);

    // Update total compartment size, by adding additional scratch + extra
    // (TLS, environ) memory needs
    new_comp->total_size += new_comp->scratch_mem_size;

    // All data collected; map compartment to a staging area ...
    stage_comp(new_comp);

    // ... and perform relocations
    resolve_rela_syms(new_comp);

    // Compartment size sanity check
    assert(new_comp->total_size
        == align_up(new_comp->data_size, new_comp->page_size)
            + // size of loaded ELF files
            new_comp->page_size + // buffer
            new_comp->scratch_mem_size // size of scratch memory
    );
    assert(new_comp->scratch_mem_size % new_comp->page_size == 0);

    /* Check correct scratch memory layout; we expect the stack and the heap to
     * reside consecutively, with the heap at the edge of the compartment
     * boundary, and any extra memory required residing before the stack.
     *
     * Potential extra memory regions: TLS, environ
     */
    assert((char *) new_comp->scratch_mem_base + new_comp->scratch_mem_extra
            + new_comp->scratch_mem_stack_size
        == new_comp->scratch_mem_stack_top);
    assert(new_comp->environ_sz + new_comp->total_tls_size
        == new_comp->scratch_mem_extra);

    print_comp_simple(new_comp);
    return new_comp;
}

void
comp_clean(struct Compartment *to_clean)
{
    struct LibDependency *curr_lib_dep;
    for (size_t i = 0; i < to_clean->libs_count; ++i)
    {
        size_t j;
        curr_lib_dep = to_clean->libs[i];

        // Clean library segments
        free(curr_lib_dep->lib_segs);

        // Clean library symbol data
        lib_syms_clean_deep(curr_lib_dep->lib_syms);

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
    struct CompEntryPointDef curr_cep;
    for (size_t i = 0; i < to_clean->cc->entry_point_count; ++i)
    {
        curr_cep = to_clean->cc->entry_points[i];
        for (size_t j = 0; j < curr_cep.arg_count; ++j)
        {
            free(curr_cep.args_type[j]);
        }
        free(curr_cep.args_type);
        free(curr_cep.name);
    }
    free(to_clean->cc->entry_points);
    free(to_clean->cc);
    free(to_clean->libs);
    comp_syms_clean_deep(to_clean->comp_syms);
    if (to_clean->libs_tls_sects)
    {
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
        if (getenv(libs_path_env_var) == NULL)
        {
            errx(1,
                "Environment variable `%s` for library dependencies paths not "
                "set!",
                libs_path_env_var);
        }
        lib_path = find_in_dir(lib_name, getenv(libs_path_env_var));
        if (!lib_path)
        {
            errx(1, "Did not find file for lib `%s`!", lib_name);
        }
        lib_fd = open(lib_path, O_RDONLY);
        if (lib_fd == -1)
        {
            err(1, "Error opening compartment file %s", lib_name);
        }
    }

    struct stat lib_fd_stat;
    if (fstat(lib_fd, &lib_fd_stat) == -1)
    {
        err(1, "Error accessing data for file %s", lib_path);
    }
    void *lib_data
        = mmap(NULL, lib_fd_stat.st_size, PROT_READ, MAP_PRIVATE, lib_fd, 0);
    close(lib_fd);

    // Read ELF headers
    Elf64_Ehdr lib_ehdr;
    get_lib_data(&lib_ehdr, lib_data, sizeof(Elf64_Ehdr), 0);

    if (lib_ehdr.e_type != ET_DYN)
    {
        errx(1,
            "Error parsing `%s` - only supporting ELFs of type DYN (shared "
            "object files)!",
            lib_path);
    }

    struct LibDependency *new_lib = lib_init();
    new_lib->data_base = lib_data;
    new_lib->data_size = lib_fd_stat.st_size;
    new_lib->lib_name = malloc(strlen(lib_name) + 1);
    strcpy(new_lib->lib_name, lib_name);
    if (lib_path)
    {
        new_lib->lib_path = lib_path;
    }
    else
    {
        new_lib->lib_path = malloc(strlen(lib_name) + 1);
        strcpy(new_lib->lib_path, lib_name);
    }

    parse_lib_segs(&lib_ehdr, lib_data, new_lib, new_comp);

    // Load `.shstr` section, so we can check section names
    Elf64_Shdr shstrtab_hdr;
    get_lib_data(&shstrtab_hdr, lib_data, sizeof(Elf64_Shdr),
        lib_ehdr.e_shoff + lib_ehdr.e_shstrndx * sizeof(Elf64_Shdr));
    char *shstrtab = (char *) seek_lib_data(lib_data, shstrtab_hdr.sh_offset);

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
    Elf64_Shdr curr_shdr;
    for (size_t i = 0; i < lib_ehdr.e_shnum; ++i)
    {
        get_lib_data(&curr_shdr, lib_data, sizeof(Elf64_Shdr),
            lib_ehdr.e_shoff + i * sizeof(Elf64_Shdr));

        if (curr_shdr.sh_type == SHT_SYMTAB || curr_shdr.sh_type == SHT_DYNSYM)
        {
            parse_lib_symtb(&curr_shdr, &lib_ehdr, lib_data, new_lib);
        }
        // Lookup `.rela.plt` to eagerly load relocatable function addresses
        else if (curr_shdr.sh_type == SHT_RELA
            && !strcmp(&shstrtab[curr_shdr.sh_name], ".rela.plt"))
        {
            parse_lib_rela(&curr_shdr, &lib_ehdr, lib_data, new_lib);
        }
        else if (curr_shdr.sh_type == SHT_RELA
            && !strcmp(&shstrtab[curr_shdr.sh_name], ".rela.dyn"))
        {
            parse_lib_rela(&curr_shdr, &lib_ehdr, lib_data, new_lib);
        }
        // Lookup `.dynamic` to find library dependencies
        else if (curr_shdr.sh_type == SHT_DYNAMIC)
        {
            parse_lib_dynamic_deps(&curr_shdr, &lib_ehdr, lib_data, new_lib);
        }
        // Section containing TLS static data
        else if (curr_shdr.sh_type == SHT_PROGBITS
            && curr_shdr.sh_flags & SHF_TLS)
        {
            assert(new_lib->tls_sec_addr);
            new_lib->tls_data_size = curr_shdr.sh_size;
        }
    }

    new_comp->libs_count += 1;
    new_comp->libs = realloc(
        new_comp->libs, new_comp->libs_count * sizeof(struct LibDependency *));
    new_comp->libs[new_comp->libs_count - 1] = new_lib;
    if (new_lib->lib_syms)
    {
        update_comp_syms(
            new_comp->comp_syms, new_lib->lib_syms, new_comp->libs_count - 1);
    }

    return new_lib;
}

static void
parse_lib_segs(Elf64_Ehdr *lib_ehdr, void *lib_data,
    struct LibDependency *lib_dep, struct Compartment *new_comp)
{
    // Get segment data
    Elf64_Phdr lib_phdr;
    for (size_t i = 0; i < lib_ehdr->e_phnum; ++i)
    {
        get_lib_data(&lib_phdr, lib_data, sizeof(Elf64_Phdr),
            lib_ehdr->e_phoff + i * sizeof(lib_phdr));

        if (lib_phdr.p_type == PT_TLS)
        {
            if (!new_comp->libs_tls_sects)
            {
                new_comp->libs_tls_sects = malloc(sizeof(struct TLSDesc));
            }
            lib_dep->tls_sec_addr = (void *) lib_phdr.p_vaddr;
            lib_dep->tls_sec_off = lib_phdr.p_offset;
            lib_dep->tls_sec_size = lib_phdr.p_memsz;
        }

        if (lib_phdr.p_type != PT_LOAD)
        {
            continue;
        }

        struct SegmentMap *this_seg = malloc(sizeof(struct SegmentMap));
        this_seg->mem_bot = (void *) lib_phdr.p_vaddr;
        this_seg->offset = lib_phdr.p_offset;
        this_seg->mem_sz = lib_phdr.p_memsz;
        this_seg->file_sz = lib_phdr.p_filesz;
        this_seg->prot_flags = (lib_phdr.p_flags & PF_R ? PROT_READ : 0)
            | (lib_phdr.p_flags & PF_W ? PROT_WRITE : 0)
            | (lib_phdr.p_flags & PF_X ? PROT_EXEC : 0);

        lib_dep->lib_segs_count += 1;
        lib_dep->lib_segs_size += align_up(this_seg->mem_sz, lib_phdr.p_align);
        lib_dep->lib_segs = realloc(lib_dep->lib_segs,
            lib_dep->lib_segs_count * sizeof(struct SegmentMap));
        memcpy(&lib_dep->lib_segs[lib_dep->lib_segs_count - 1], this_seg,
            sizeof(struct SegmentMap));
        free(this_seg);
    }
    lib_dep->lib_mem_base
        = align_up((char *) new_comp->data_size + new_comp->page_size,
            new_comp->page_size);
    new_comp->data_size += lib_dep->lib_segs_size;
}

static void
parse_lib_symtb(Elf64_Shdr *symtb_shdr, Elf64_Ehdr *lib_ehdr, void *lib_data,
    struct LibDependency *lib_dep)
{
    // Get symbol table
    Elf64_Shdr link_shdr;
    assert(symtb_shdr->sh_link);
    get_lib_data(&link_shdr, lib_data, sizeof(Elf64_Shdr),
        lib_ehdr->e_shoff + symtb_shdr->sh_link * sizeof(Elf64_Shdr));

    Elf64_Sym *sym_tb
        = (Elf64_Sym *) seek_lib_data(lib_data, symtb_shdr->sh_offset);
    char *str_tb = (char *) seek_lib_data(lib_data, link_shdr.sh_offset);

    size_t lib_syms_count = symtb_shdr->sh_size / sizeof(Elf64_Sym);
    size_t actual_syms = 0;

    if (!lib_dep->lib_syms)
    {
        lib_dep->lib_syms = lib_syms_init();
    }

    Elf64_Sym curr_sym;
    lib_symbol *to_insert;
    for (size_t j = 0; j < lib_syms_count; ++j)
    {
        curr_sym = sym_tb[j];
        // TODO currently ignore symbols of unspecified type
        if (ELF_ST_TYPE(curr_sym.st_info) == STT_NOTYPE)
        {
            continue;
        }

        to_insert = malloc(sizeof(lib_symbol));
        to_insert->sym_offset = (void *) curr_sym.st_value;
        char *sym_name = &str_tb[curr_sym.st_name];
        to_insert->sym_name = malloc(strlen(sym_name) + 1);
        strcpy(to_insert->sym_name, sym_name);
        to_insert->sym_type = ELF64_ST_TYPE(curr_sym.st_info);
        to_insert->sym_bind = ELF64_ST_BIND(curr_sym.st_info);
        to_insert->sym_shndx = curr_sym.st_shndx;
        lib_syms_insert(to_insert, lib_dep->lib_syms);
    }
}

static void
parse_lib_rela(Elf64_Shdr *rela_shdr, Elf64_Ehdr *lib_ehdr, void *lib_data,
    struct LibDependency *lib_dep)
{
    // Traverse `.rela.plt`, so we can see which function addresses we need
    // to eagerly load
    Elf64_Rela *rela_sec
        = (Elf64_Rela *) seek_lib_data(lib_data, rela_shdr->sh_offset);
    size_t rela_count = rela_shdr->sh_size / sizeof(Elf64_Rela);

    Elf64_Shdr dyn_sym_hdr;
    get_lib_data(&dyn_sym_hdr, lib_data, sizeof(Elf64_Shdr),
        lib_ehdr->e_shoff + rela_shdr->sh_link * sizeof(Elf64_Shdr));
    Elf64_Sym *dyn_sym_tbl
        = (Elf64_Sym *) seek_lib_data(lib_data, dyn_sym_hdr.sh_offset);

    Elf64_Shdr dyn_str_hdr;
    get_lib_data(&dyn_str_hdr, lib_data, sizeof(Elf64_Shdr),
        lib_ehdr->e_shoff + dyn_sym_hdr.sh_link * sizeof(Elf64_Shdr));
    char *dyn_str_tbl = (char *) seek_lib_data(lib_data, dyn_str_hdr.sh_offset);

    // XXX Since TLSDESC entries might resolve to two relocation slots, we
    // ensure we have enough space by doubling the expected relocation counts
    struct LibRelaMapping *new_relas
        = malloc(2 * rela_count * sizeof(struct LibRelaMapping));

    // Prepare TLS look-up function relocation (will be copied for each TLS
    // relocation entry
    static struct LibRelaMapping tls_lrm
        = { NULL, 0x0, 0x0, -1, STT_FUNC, STB_GLOBAL, 0, true };

    // Log symbols that will need to be relocated eagerly at maptime
    Elf64_Rela curr_rela;
    size_t actual_relas = 0;
    for (size_t j = 0; j < rela_count; ++j)
    {
        curr_rela = rela_sec[j];
        size_t curr_rela_sym_idx = ELF64_R_SYM(curr_rela.r_info);
        size_t curr_rela_type = ELF64_R_TYPE(curr_rela.r_info);

        struct LibRelaMapping lrm
            = { NULL, 0x0, 0x0, curr_rela_type, -1, -1, 0, true };

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
                lrm.rela_sym_shndx = 1; // TODO better index?
                lrm.target_func_address = (void *) curr_rela.r_addend;
            }
            else
            {
                Elf64_Sym curr_rela_sym = dyn_sym_tbl[curr_rela_sym_idx];
                lrm.rela_name
                    = malloc(strlen(&dyn_str_tbl[curr_rela_sym.st_name]) + 1);
                strcpy(lrm.rela_name, &dyn_str_tbl[curr_rela_sym.st_name]);
                lrm.rela_sym_type = ELF64_ST_TYPE(curr_rela_sym.st_info);
                lrm.rela_sym_bind = ELF64_ST_BIND(curr_rela_sym.st_info);
                lrm.rela_sym_shndx = curr_rela_sym.st_shndx;
                if (lrm.rela_sym_shndx != 0)
                {
                    lrm.target_func_address = (void *) curr_rela_sym.st_value;
                }
            }

            // Offset relocation address by one slot, due to the lookup
            // function relocation
            lrm.rela_address = curr_rela.r_offset
                + (char *) lib_dep->lib_mem_base + sizeof(void *);

            // Do not update address in mapping for TLS variables
            lrm.mapping_reloc = false;
        }
        else if (curr_rela_type == R_AARCH64_TLS_TPREL64)
        {
            lrm.mapping_reloc = false;
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
                if (!strcmp(&dyn_str_tbl[curr_rela_sym.st_name], "__progname"))
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
                lrm.rela_sym_shndx = curr_rela_sym.st_shndx;
                if (lrm.rela_sym_shndx != 0 && lrm.rela_sym_bind != STB_WEAK)
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
}

static void
parse_lib_dynamic_deps(Elf64_Shdr *dynamic_shdr, Elf64_Ehdr *lib_ehdr,
    void *lib_data, struct LibDependency *lib_dep)
{
    // Find additional library dependencies
    Elf64_Dyn *dyn_entries
        = (Elf64_Dyn *) seek_lib_data(lib_data, dynamic_shdr->sh_offset);
    Elf64_Shdr dynstr_shdr;
    get_lib_data(&dynstr_shdr, lib_data, sizeof(Elf64_Shdr),
        lib_ehdr->e_shoff + dynamic_shdr->sh_link * sizeof(Elf64_Shdr));
    char *dynstr_tbl = (char *) seek_lib_data(lib_data, dynstr_shdr.sh_offset);

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
}

static void
map_comp_entry_points(struct Compartment *new_comp)
{
    for (size_t i = 0; i < new_comp->cc->entry_point_count; ++i)
    {
        // TODO are entry points always in the main loaded library?
        // TODO is the main loaded library always the 0th indexed one?
        const size_t lib_idx = 0;
        const char *ep_name = new_comp->cc->entry_points[i].name;
        lib_symbol **candidates
            = lib_syms_find_all(ep_name, new_comp->libs[lib_idx]->lib_syms);
        size_t j = 0;
        while (candidates)
        {
            if (check_lib_dep_sym(*candidates, STT_FUNC))
            {
                break;
            }
            *candidates += sizeof(lib_symbol *);
        }
        if (!candidates)
        {
            errx(1, "Did not find entry point %s!\n", ep_name);
        }
        new_comp->cc->entry_points[i].comp_addr
            = eval_lib_sym_offset(new_comp, lib_idx, *candidates);
        free(candidates);
    }
}

/* Resolve relocations with compartment relative addresses
 *
 * The way AARCH64 relocations work is that they use relative addresses for the
 * lookup, so we only need to resolve the addresses within the compartment,
 * without needing to know where the compartment will eventually be mapped in
 * actual memory
 */
static void
resolve_rela_syms(struct Compartment *new_comp)
{
    // Find all symbols for eager relocation mapping
    size_t prev_tls_secs_size = 0;
    struct LibRelaMapping *curr_rela_map;
    comp_symbol **candidate_syms;
    comp_symbol *chosen_sym;
    void *rela_target;
    for (size_t i = 0; i < new_comp->libs_count; ++i)
    {
        for (size_t j = 0; j < new_comp->libs[i]->rela_maps_count; ++j)
        {
            curr_rela_map = &new_comp->libs[i]->rela_maps[j];
            chosen_sym = NULL;

            // This is a TLS variable that exists in the current library; we
            // just allocate the space for it
            if (curr_rela_map->rela_sym_type == STT_TLS
                && curr_rela_map->rela_sym_shndx != 0)
            {
                *((void **) ((char *) new_comp->staged_addr
                    + (uintptr_t) curr_rela_map->rela_address))
                    = (char *) curr_rela_map->target_func_address
                    + prev_tls_secs_size;
                continue;
            }

            if (curr_rela_map->rela_type == R_AARCH64_TLS_TPREL64)
            {
                *((void **) ((char *) new_comp->staged_addr
                    + (uintptr_t) curr_rela_map->rela_address))
                    = (char *) curr_rela_map->target_func_address
                    + prev_tls_secs_size;
                continue;
            }

            if (curr_rela_map->target_func_address != 0)
            {
                continue;
            }

            if (curr_rela_map->rela_name
                && !strcmp(curr_rela_map->rela_name, tls_rtld_dropin))
            {
                curr_rela_map->target_func_address = new_comp->tls_lookup_func;
                continue;
            }

            if (curr_rela_map->rela_name
                && !strcmp(curr_rela_map->rela_name, "environ"))
            {
                curr_rela_map->target_func_address = new_comp->environ_ptr;
                continue;
            }

            candidate_syms = comp_syms_find_all(
                curr_rela_map->rela_name, new_comp->comp_syms);

            if (*candidate_syms == NULL)
            {
                if (curr_rela_map->rela_sym_bind == STB_WEAK)
                {
                    // TODO Hack to suppress weak `libc` relocations
                    const char *lib_to_suppress = "libc.so";
                    if (strlen(new_comp->libs[i]->lib_name)
                            > strlen(lib_to_suppress)
                        && strncmp(new_comp->libs[i]->lib_name, lib_to_suppress,
                            strlen(lib_to_suppress)))
                    {
                        warnx("Did not find WEAK symbol %s of type %hu (idx "
                              "%zu in library %s (idx %zu)) - execution "
                              "*might* fault.",
                            curr_rela_map->rela_name,
                            curr_rela_map->rela_sym_type, j,
                            new_comp->libs[i]->lib_name, i);
                    }
                    free(candidate_syms);
                    continue;
                }

                errx(1,
                    "Did not find symbol %s of type %hu (idx %zu in "
                    "library %s "
                    "(idx %zu))!",
                    curr_rela_map->rela_name, curr_rela_map->rela_sym_type, j,
                    new_comp->libs[i]->lib_name, i);
            }

            // Prioritise looking for weak symbols in libraries outside the
            // source library, even if they are defined
            if (curr_rela_map->rela_sym_bind == STB_WEAK)
            {
                comp_symbol *fallback_sym = NULL;
                comp_symbol **candidate_syms_iter = candidate_syms;
                while (*candidate_syms_iter)
                {
                    if (check_lib_dep_sym((*candidate_syms_iter)->sym_ref,
                            curr_rela_map->rela_sym_type))
                    {
                        if ((*candidate_syms_iter)->sym_lib_idx != i)
                        {
                            chosen_sym = *candidate_syms_iter;
                            break;
                        }
                        else if (!fallback_sym)
                        {
                            fallback_sym = *candidate_syms_iter;
                        }
                    }
                    candidate_syms_iter += 1;
                }
                if (!chosen_sym)
                {
                    assert(fallback_sym);
                    chosen_sym = fallback_sym;
                }
            }
            else
            {
                // Choose the first candidate
                // TODO is there a better choice?
                chosen_sym = *candidate_syms;
            }
            free(candidate_syms);

            // TODO collapse?
            if (curr_rela_map->rela_sym_type == STT_TLS)
            {
                rela_target = eval_staged_sym_tls_offset(new_comp, chosen_sym);
                memcpy((char *) new_comp->staged_addr
                        + (uintptr_t) curr_rela_map->rela_address,
                    &rela_target, sizeof(void *));
            }
            else
            {
                curr_rela_map->target_func_address
                    = eval_staged_sym_offset(new_comp, chosen_sym);
            }
        }
        prev_tls_secs_size += new_comp->libs[i]->tls_sec_size;
    }
}

/* Search existing compartment symbols to see if we defined a
 * `tls_lookup_func`
 */
void
find_tls_lookup_func(struct Compartment *comp)
{
    comp_symbol *tls_lf = comp_syms_search(tls_rtld_dropin, comp->comp_syms);
    if (tls_lf)
    {
        comp->tls_lookup_func = eval_sym_offset(comp, tls_lf);
    }
}

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

static void
get_lib_data(void *buf, void *lib_file_addr, size_t data_sz, off_t offset)
{
    memcpy(buf, (char *) lib_file_addr + offset, data_sz);
}

static void *
seek_lib_data(void *lib_data, off_t offset)
{
    return (void *) ((char *) lib_data + offset);
}

void *
get_seg_target(void *base_addr, struct LibDependency *lib_dep, size_t seg_id)
{
    return (char *) base_addr + (uintptr_t) lib_dep->lib_mem_base
        + (uintptr_t) lib_dep->lib_segs[seg_id].mem_bot;
}

static void *
eval_staged_sym_offset(struct Compartment *comp, const comp_symbol *sym)
{
    assert(comp->staged_addr != NULL);
    return (char *) comp->libs[sym->sym_lib_idx]->lib_mem_base
        + (uintptr_t) sym->sym_ref->sym_offset;
}

static void *
eval_staged_sym_tls_offset(struct Compartment *comp, const comp_symbol *sym)
{
    return (char *) sym->sym_ref->sym_offset
        + comp->libs[sym->sym_lib_idx]->tls_offset; // TODO check offset type
}

static void *
eval_sym_offset(struct Compartment *comp, const comp_symbol *sym)
{
    return (char *) comp->libs[sym->sym_lib_idx]->lib_mem_base
        + (uintptr_t) sym->sym_ref->sym_offset;
}

static void *
eval_lib_sym_offset(
    struct Compartment *comp, const size_t lib_idx, const lib_symbol *sym)
{
    return (char *) comp->libs[lib_idx]->lib_mem_base
        + (uintptr_t) sym->sym_offset;
}

// TODO relocate all `NOTYPE` symbols to same symbol - cache?
static bool
check_lib_dep_sym(lib_symbol *sym, const unsigned short rela_type)
{
    return
        // Ignore `LOCAL` bind symbols - they cannot be relocated against
        sym->sym_bind != STB_LOCAL &&
        // Check symbol is indeed local, not another external reference
        sym->sym_shndx != 0 &&
        // Check symbol type matches, or relocation is `NOTYPE`
        (rela_type == STT_NOTYPE || sym->sym_type == rela_type);
}

static char *
find_in_dir(const char *const lib_name, char *search_dir)
{
    char *res = NULL;
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
            res = malloc(curr_entry->fts_pathlen + 1);
            strcpy(res, curr_entry->fts_path);
            break;
        }
    }
    fts_close(dir);
    free(search_paths);
    if (curr_entry != NULL)
    {
        return res;
    }
    return NULL;
}

/* Lay out compartment's stack and heap. They each grow from
 * `scratch_mem_stack_top`, with the stack growing downward, and the heap
 * growing upwards. The heap shall reside at the edge of the DDC, such that any
 * heap overflows will trigger a SIGPROT. Any further scratch memory required
 * (such as for TLS) will be added at `scratch_mem_base`, and
 * `scratch_mem_stack_top` will be adjusted appropriately, via
 * `adjust_comp_scratch_mem()`.
 */
static void
init_comp_scratch_mem(struct Compartment *new_comp)
{
    new_comp->scratch_mem_base = (void *) new_comp->total_size;
    new_comp->scratch_mem_heap_size = new_comp->cc->heap_size;
    new_comp->scratch_mem_stack_size = new_comp->cc->stack_size;
    new_comp->scratch_mem_stack_top = align_down(
        (char *) new_comp->scratch_mem_base + new_comp->scratch_mem_stack_size,
        16);

    new_comp->scratch_mem_size
        = new_comp->scratch_mem_heap_size + new_comp->scratch_mem_stack_size;

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
    assert(new_comp->scratch_mem_size % new_comp->page_size == 0);
}

static void
adjust_comp_scratch_mem(struct Compartment *new_comp, size_t to_adjust)
{
    assert(to_adjust % new_comp->page_size == 0);
    new_comp->scratch_mem_size += to_adjust;
    new_comp->scratch_mem_stack_top
        = (char *) new_comp->scratch_mem_stack_top + to_adjust;
    new_comp->scratch_mem_extra += to_adjust;
}

/* New scratch regions will be added after previous extra regions
 */
static inline void *
get_extra_scratch_region_base(struct Compartment *new_comp)
{
    char *new_scratch_region_base
        = (char *) new_comp->scratch_mem_base + new_comp->scratch_mem_extra;
    assert((intptr_t) new_scratch_region_base % new_comp->page_size == 0);
    return new_scratch_region_base;
}

static void
setup_environ(struct Compartment *new_comp)
{
    assert(new_comp->cc->env_ptr != NULL); // TODO consider optional check
    new_comp->environ_sz
        = align_up(new_comp->cc->env_ptr_sz, new_comp->page_size)
        + new_comp->page_size;
    new_comp->environ_ptr = get_extra_scratch_region_base(new_comp);
    adjust_comp_scratch_mem(new_comp, new_comp->environ_sz);
}

static void
resolve_comp_tls_regions(struct Compartment *new_comp)
{
    if (!new_comp->libs_tls_sects)
    {
        return;
    }

    find_tls_lookup_func(new_comp);
    assert(new_comp->tls_lookup_func);

    // TODO currently we only support one thread
    new_comp->libs_tls_sects->region_count = 1;
    new_comp->libs_tls_sects->region_start
        = get_extra_scratch_region_base(new_comp);
    new_comp->libs_tls_sects->libs_count = 0;

    size_t comp_tls_size = 0;
    for (size_t i = 0; i < new_comp->libs_count; ++i)
    {
        if (new_comp->libs[i]->tls_sec_addr == 0x0)
        {
            continue;
        }

        new_comp->libs[i]->tls_offset = comp_tls_size;
        comp_tls_size += new_comp->libs[i]->tls_sec_size;
        new_comp->libs_tls_sects->libs_count += 1;
    }
    comp_tls_size = align_up(comp_tls_size, 16);

    intptr_t total_tls_size
        = comp_tls_size * new_comp->libs_tls_sects->region_count;
    total_tls_size = align_up(total_tls_size, new_comp->page_size);
    adjust_comp_scratch_mem(new_comp, total_tls_size);
    new_comp->total_tls_size = total_tls_size;
    new_comp->libs_tls_sects->region_size = comp_tls_size;
}

static void
stage_comp(struct Compartment *to_stage)
{
    void *base_stage_addr = mmap(NULL, to_stage->total_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base_stage_addr == MAP_FAILED)
    {
        err(1, "Error staging compartment %zu", to_stage->id);
    }

    // Copy over segment data and `.tdata`
    struct LibDependency *lib_dep;
    struct SegmentMap lib_dep_seg;
    size_t tls_allocd = 0x0;
    for (size_t i = 0; i < to_stage->libs_count; ++i)
    {
        lib_dep = to_stage->libs[i];

        // Segment data
        for (size_t j = 0; j < lib_dep->lib_segs_count; ++j)
        {
            lib_dep_seg = lib_dep->lib_segs[j];
            memcpy(get_seg_target(base_stage_addr, lib_dep, j),
                (char *) lib_dep->data_base + lib_dep_seg.offset,
                lib_dep_seg.file_sz);
        }

        // `.tdata` for TLS
        if (to_stage->libs[i]->tls_sec_size != 0)
        {
            assert(to_stage->libs[i]->tls_sec_addr != 0x0);
            memcpy((char *) base_stage_addr
                    + (uintptr_t) to_stage->libs_tls_sects->region_start
                    + (uintptr_t) tls_allocd,
                (char *) lib_dep->data_base
                    + (uintptr_t) to_stage->libs[i]->tls_sec_off,
                lib_dep->tls_sec_size);
            tls_allocd += to_stage->libs[i]->tls_sec_size;
        }

        munmap(lib_dep->data_base, lib_dep->data_size);
        lib_dep->data_base = NULL;
        lib_dep->data_size = 0;
    }

    /* Copy over environ variables
     *
     * We need a pointer to an array of string pointers, so we synthetically
     * create one. We don't expect this pointer to move, as the maximum allowed
     * size for the `environ` array is already allocated
     */

    void *environ_addr
        = (char *) to_stage->environ_ptr + (uintptr_t) base_stage_addr;
    *((uintptr_t *) environ_addr) = sizeof(void *);
    environ_addr = (char *) environ_addr + sizeof(char *);

    // Copy over prepared `environ` data from manager
    memcpy(environ_addr, to_stage->cc->env_ptr, to_stage->cc->env_ptr_sz);

    to_stage->staged_addr = base_stage_addr;
}

/*******************************************************************************
 * Print functions
 ******************************************************************************/
static void
print_lib_dep_seg(struct SegmentMap *lib_dep_seg)
{
    printf(">> bot %p // off 0x%zx // msz 0x%zx // fsz "
           "0x%zx\n",
        lib_dep_seg->mem_bot, lib_dep_seg->offset, lib_dep_seg->mem_sz,
        lib_dep_seg->file_sz);
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

    // TODO lib_syms

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
print_comp_simple(struct Compartment *to_print)
{
    printf("== COMPARTMENT SIMPLE -- ID %zu\n", to_print->id);
    printf("-- staged_addr : %p\n", to_print->staged_addr);
    printf("-- total_size : %#zx\n", to_print->total_size);
    printf("-- data_size: %#zx\n", to_print->data_size);
    for (size_t i = 0; i < to_print->libs_count; ++i)
    {
        printf("\t* lib %zu `%s` >> %p\n", i, to_print->libs[i]->lib_name,
            to_print->libs[i]->lib_mem_base);
    }
}
