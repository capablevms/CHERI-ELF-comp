#include "manager.h"
#include "limits.h"

extern struct Compartment* loaded_comp;

char*
get_full_path(char* path)
{
    char buf[PATH_MAX];
    char* res = realpath(path, buf);
    assert(res != NULL);
    return res;
}

int
main(int argc, char** argv)
{
    manager_ddc = cheri_ddc_get();
    time_t t_buf;
    time(&t_buf);
    assert(argc == 2);
    char* file = argv[1];
    struct Compartment* hw_comp = comp_from_elf(file);
    loaded_comp = hw_comp; // TODO
    hw_comp->argc = 1;
    char* comp_argv[] = { get_full_path(file) };
    hw_comp->argv = comp_argv;
    log_new_comp(hw_comp);
    comp_print(hw_comp);
    comp_map(hw_comp);
    int comp_result = comp_exec(hw_comp);
    comp_clean(hw_comp);
    return comp_result;
}
