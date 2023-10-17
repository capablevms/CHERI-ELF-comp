# Manager executables
add_executable(manager_call
    ${TEST_DIR}/manager_caller.c
    )
target_include_directories(manager_call PUBLIC ${INCLUDE_DIR} ${TOML_INCLUDE_DIR})
target_link_libraries(manager_call PUBLIC chcomp)

add_executable(manager_args
    ${TEST_DIR}/manager_arg_passer.c
    )
target_include_directories(manager_args PUBLIC ${INCLUDE_DIR} ${TOML_INCLUDE_DIR})
target_link_libraries(manager_args PUBLIC chcomp)

# Test properties
define_property(TARGET
                PROPERTY compartment
                BRIEF_DOCS "Whether this target is a CHERI compartment."
                FULL_DOCS "Whether this target is a CHERI compartment.")

define_property(TARGET
                PROPERTY compartment_config
                BRIEF_DOCS "A compartment configuration file associated with a compartment source file."
                FULL_DOCS "A compartment configuration file associated with a compartment source file.")

define_property(TARGET
                PROPERTY extra_deps
                BRIEF_DOCS "Additional file dependencies to run a test."
                FULL_DOCS "Additional file dependencies to run a test.")

# Helper functions
function(get_deps target)
    set(deps_var "")
    list(APPEND deps_var $<TARGET_FILE:${target}>)
    get_property(has_config TARGET ${target} PROPERTY compartment_config SET)
    if(has_config)
        list(APPEND deps_var $<TARGET_PROPERTY:${target},compartment_config>)
    endif()
    get_property(has_deps TARGET ${target} PROPERTY extra_deps SET)
    if(has_deps)
        get_property(prop_deps TARGET ${target} PROPERTY extra_deps)
        list(APPEND deps_var ${prop_deps})
    endif()
    set(deps_var ${deps_var} PARENT_SCOPE)
endfunction()

# Library test functions
function(new_target test_name compartment)
    add_executable(${test_name}
        ${test_name}.c)
    target_link_libraries(${test_name} PRIVATE chcomp dl m)
    target_link_libraries(${test_name} PRIVATE lualib)
    target_include_directories(${test_name} PRIVATE ${INCLUDE_DIR} ${LUA_INCLUDE_DIR})
    if(${compartment})
        target_compile_options(${test_name} PRIVATE -static)
        if(${ARGC} GREATER 2)
            target_link_options(${test_name} PRIVATE -static "LINKER:-image-base=${ARGV2}")
        else()
            target_link_options(${test_name} PRIVATE -static "LINKER:-image-base=0x1000000")
        endif()
        set_property(TARGET ${test_name} PROPERTY compartment TRUE)
        if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.comp)
            set_property(TARGET ${test_name} PROPERTY compartment_config ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.comp)
        endif()
    else()
        target_link_libraries(${test_name} PRIVATE tomllib)
        target_include_directories(${test_name} PRIVATE ${TOML_INCLUDE_DIR})
    endif()
endfunction()

function(new_test test_name test_runner test_bin)
    if(test_bin)
        get_deps(${test_bin})
    else()
        get_deps(${test_runner})
    endif()
    list(PREPEND test_cmd ${deps_var})
    if(test_cmd)
        list(PREPEND test_cmd "--dependencies")
    endif()
    if(test_bin)
        list(PREPEND test_cmd ${ARGN})
        list(PREPEND test_cmd ${test_bin})
        list(PREPEND test_cmd "--test-args")
    endif()
    list(PREPEND test_cmd $<TARGET_FILE_NAME:${test_runner}>)
    add_test(NAME ${test_name}
             COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.py ${test_cmd}
             COMMAND_EXPAND_LISTS)
endfunction()

function(new_dependency target dep_file)
    set_property(TARGET ${target} APPEND PROPERTY extra_deps ${dep_file})
endfunction()

# Binaries to build
set(func_binaries
    "test_map"
    "test_args_near_unmapped"
    "test_ddc_overwrite_manager"
    "test_two_comps"
    "test_two_comps_inter_call"
    )

set(comp_binaries
    "simple"
    "time"
    "lua_simple"
    "lua_script"
    "args_simple"
    "test_ddc_overwrite"
    "test_two_comps-comp1"
    "test_two_comps-comp2 0x2000000"
    )

# Tests with no arguments
set(tests_direct
    "test_map"
    "test_args_near_unmapped"
    "test_two_comps"
    "test_two_comps_inter_call"
    "test_ddc_overwrite_manager"
    )

# Tests with arguments
# FORMAT : <test_name> <binary> <binary_args> [...]
set(tests_args
    "simple manager_call simple"
    "time manager_call time"
    "lua_simple manager_call lua_simple"
    "lua_script manager_call lua_script"
    "args-simple manager_args args_simple check_simple 40 2"
    "args-more manager_args args_simple check_simple 40 2 2 2" # Check additional arguments are ignored
    "args-combined manager_args args_simple check_combined 400 2 20"
    "args-negative manager_args args_simple check_negative -42"
    "args-long-max manager_args args_simple check_llong_max 9223372036854775807"
    "args-long-min manager_args args_simple check_llong_min -9223372036854775808"
    "args-ulong-max manager_args args_simple check_ullong_max 18446744073709551615"
    )

#  Build targets
foreach(comp_t IN LISTS comp_binaries)
    string(FIND ${comp_t} " " space_pos)
    if(${space_pos} EQUAL -1)
        new_target(${comp_t} TRUE)
    else()
        string(SUBSTRING ${comp_t} 0 ${space_pos} tgt_name)
        string(SUBSTRING ${comp_t} ${space_pos} -1 img_base)
        string(STRIP ${img_base} img_base)
        new_target(${tgt_name} TRUE ${img_base})
    endif()
endforeach()

foreach(func_t IN LISTS func_binaries)
    new_target(${func_t} FALSE)
endforeach()


# Additional dependencies
new_dependency(test_map $<TARGET_FILE:simple>)
new_dependency(test_args_near_unmapped $<TARGET_FILE:args_simple>)
new_dependency(test_args_near_unmapped ${CMAKE_CURRENT_SOURCE_DIR}/args_simple.comp)

new_dependency(test_two_comps $<TARGET_FILE:test_two_comps-comp1>)
new_dependency(test_two_comps $<TARGET_FILE:test_two_comps-comp2>)
new_dependency(test_two_comps ${CMAKE_CURRENT_SOURCE_DIR}/test_two_comps-comp1.comp)

new_dependency(test_two_comps_inter_call $<TARGET_FILE:test_two_comps-comp1>)
new_dependency(test_two_comps_inter_call $<TARGET_FILE:test_two_comps-comp2>)
new_dependency(test_two_comps_inter_call ${CMAKE_CURRENT_SOURCE_DIR}/test_two_comps-comp1.comp)

new_dependency(test_ddc_overwrite_manager $<TARGET_FILE:test_ddc_overwrite>)
new_dependency(test_ddc_overwrite_manager ${CMAKE_CURRENT_SOURCE_DIR}/test_ddc_overwrite.comp)

new_dependency(lua_script ${CMAKE_CURRENT_SOURCE_DIR}/hello_world.lua)

foreach(test_d IN LISTS tests_direct)
    new_test(${test_d} ${test_d} "" "")
endforeach()

# Prepare tests
foreach(test_a IN LISTS tests_args)
    string(REPLACE " " ";" test_args_list ${test_a})
    list(GET test_args_list 0 test_name)
    list(GET test_args_list 1 test_runner)
    list(GET test_args_list 2 test_bin)
    list(LENGTH test_args_list test_args_len)
    if(${test_args_len} GREATER 3)
        list(SUBLIST test_args_list 3 -1 test_bin_args)
    endif()
    new_test(${test_name} ${test_runner} ${test_bin} ${test_bin_args})
endforeach()
