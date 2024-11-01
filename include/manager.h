#ifndef _MANAGER_H
#define _MANAGER_H

#include <assert.h>
#include <dlfcn.h>
#include <err.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

// Third-party libraries
#include "toml.h"

#include "compartment.h"
#include "intercept.h"

#define align_down(x, align) __builtin_align_down(x, align)
#define align_up(x, align) __builtin_align_up(x, align)

extern void *__capability manager_ddc;
extern struct Compartment **comps;
extern struct Compartment *loaded_comp;

/*******************************************************************************
 * Compartment
 ******************************************************************************/

// Compartment configuration file suffix
extern const char *comp_config_suffix;

struct Compartment *
register_new_comp(char *, bool);

union arg_holder
{
    int i;
    long l;
    char c;
    long long ll;
    unsigned long long ull;
};

char *
prep_config_filename(char *);
void
clean_all_comps();
void
clean_comp(struct Compartment *);
void
clean_compartment_config(struct CompEntryPointDef *, size_t);

/*******************************************************************************
 * Compartment mappings
 ******************************************************************************/

struct CompMapping *
mapping_new(struct Compartment *);
struct CompMapping *
mapping_new_fixed(struct Compartment *, void *);
void
mapping_free(struct CompMapping *);
int64_t
mapping_exec(struct CompMapping *, char *, char **);

struct CompMapping
{
    size_t id;
    void *__capability ddc;
    void *map_addr;
    struct Compartment *comp;
};

#endif // _MANAGER_H
