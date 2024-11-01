#include "manager.h"

int
main(int argc, char **argv)
{
    const char *count_env_name = "EXECUTE_COUNT";
    const char *count_env_val = getenv(count_env_name);
    const unsigned int comps_count_default = 100;
    unsigned int comps_count
        = count_env_val ? atoi(count_env_val) : comps_count_default;

    // Initial setup
    manager_ddc = cheri_ddc_get();
    setup_intercepts();

    assert(argc >= 2
        && "Expect at least one argument: binary file for compartment");
    char *file = argv[1];

    struct Compartment *hw_comp = register_new_comp(file, true);
    int comp_result = 0;
    for (size_t i = 0; i < comps_count; ++i)
    {
        comp_map(hw_comp);
        comp_result = (exec_comp(hw_comp, "main", NULL) != 0) || comp_result;
        comp_unmap(hw_comp);
    }
    comp_clean(hw_comp);
    assert(!comp_result);
    return comp_result;
}