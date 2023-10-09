#ifndef _MANAGER_H
#define _MANAGER_H

#include <assert.h>
#include <dlfcn.h>
#include <err.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

// Third-party libraries
#include "toml.h"

#include "intercept.h"
#include "compartment.h"

#define align_down(x, align)    __builtin_align_down(x, align)
#define align_up(x, align)      __builtin_align_up(x, align)

extern void* __capability manager_ddc;
extern struct CompWithEntries** comps;
extern struct Compartment* loaded_comp;

/*******************************************************************************
 * Utility Functions
 ******************************************************************************/

void print_full_cap(uintcap_t);

/*******************************************************************************
 * Compartment
 ******************************************************************************/

// Compartment configuration file suffix
extern const char* comp_config_suffix;

/* Struct representing configuration data for one entry point; this is just
 * information that we expect to appear in the compartment, as given by its
 * compartment configuration file
 */
struct ConfigEntryPoint
{
    const char* name;
    size_t arg_count;
    char** args_type;
};

struct CompWithEntries
{
    struct Compartment* comp;
    struct ConfigEntryPoint* cep;
};

void* get_next_comp_addr(void);
struct Compartment* register_new_comp(char*, bool);
int64_t exec_comp(struct Compartment*, char*, char**);

struct Compartment* manager_find_compartment_by_addr(void*);
struct Compartment* manager_find_compartment_by_ddc(void* __capability);
struct Compartment* manager_get_compartment_by_id(size_t);


// TODO stack setup when we transition into the compartment; unsure if needed,
// but keep for now, just in case
#define ENV_FIELDS_CNT 1
extern const char* comp_env_fields[ENV_FIELDS_CNT];
extern char** environ;
const char* get_env_str(const char*);
int manager___vdso_clock_gettime(clockid_t, struct timespec*);
// END TODO

union arg_holder
{
    int i;
    long l;
    char c;
    long long ll;
    unsigned long long ull;
};

char* prep_config_filename(char*);
void clean_all_comps();
void clean_comp(struct Compartment*);
void clean_compartment_config(struct ConfigEntryPoint*, size_t);

/*******************************************************************************
 * Memory allocation
 ******************************************************************************/

#include "mem_mng.h"

#endif // _MANAGER_H
