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
extern struct CompWithEntries **comps;
extern struct Compartment *loaded_comp;

/*******************************************************************************
 * Compartment
 ******************************************************************************/

// Compartment configuration file suffix
extern const char *comp_config_suffix;

/* Struct representing configuration data for one entry point; this is just
 * information that we expect to appear in the compartment, as given by its
 * compartment configuration file
 */
struct CompEntryPointDef
{
    const char *name;
    size_t arg_count;
    char **args_type;
};

struct CompWithEntries
{
    struct Compartment *comp;
    struct CompEntryPointDef *cep;
};

void *
get_next_comp_addr(void);
struct Compartment *
register_new_comp(char *, bool);
int64_t
exec_comp(struct Compartment *, char *, char **);

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
 * Memory allocation
 ******************************************************************************/

#endif // _MANAGER_H
