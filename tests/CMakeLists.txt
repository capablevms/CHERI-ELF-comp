set(BIN_INCLUDE_DIRS ${INCLUDE_DIR} ${TOML_INCLUDE_DIR} ${TOMMYDS_DIR})
set(BIN_LINK_LIBS chcomp compbench)

# Manager executables
function(new_manager_bin bin_name)
    add_executable(${bin_name}
        ${bin_name}.c)
    target_include_directories(${bin_name} PUBLIC ${BIN_INCLUDE_DIRS})
    target_link_libraries(${bin_name} PUBLIC ${BIN_LINK_LIBS})
endfunction()

set(manager_bins
    "manager_caller"
    "manager_caller_multiple"
    "manager_arg_passer"
    "manager_arg_passer_multiple"
)

foreach(bin_t IN LISTS manager_bins)
    new_manager_bin(${bin_t})
endforeach()

# Special tests
add_executable(comp_harness EXCLUDE_FROM_ALL
    ${SRC_DIR}/symbols_comp.c
    ${SRC_DIR}/symbols_lib.c
    ${TEST_DIR}/compartment_harness.c
)
target_include_directories(comp_harness PUBLIC ${BIN_INCLUDE_DIRS})
target_link_libraries(comp_harness PUBLIC tomllib tommydslib)
target_compile_options(comp_harness BEFORE PUBLIC -fsanitize=address)
target_link_options(comp_harness BEFORE PUBLIC -fsanitize=address)

add_executable(so_harness
    ${TEST_DIR}/so_harness.c
)
target_link_libraries(so_harness PUBLIC dl)

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
function(get_deps target deps_var)
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

# Internal library tests
function(new_func_test test_name)
    add_executable(${test_name}
        ${test_name}.c)
    target_link_libraries(${test_name} PRIVATE ${BIN_LINK_LIBS})
    target_include_directories(${test_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/src ${BIN_INCLUDE_DIRS})
endfunction()

# Compartment tests
function(new_comp_test test_name)
    add_library(${test_name} SHARED
        ${test_name}.c)
    set_target_properties(${test_name} PROPERTIES PREFIX "")
    target_link_libraries(${test_name} PRIVATE computils lualib dl m)
    target_include_directories(${test_name} PRIVATE ${INCLUDE_DIR} ${LUA_INCLUDE_DIR})

    set_property(TARGET ${test_name} PROPERTY compartment TRUE)
    if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.comp)
        set_property(TARGET ${test_name}
                     PROPERTY compartment_config ${CMAKE_CURRENT_SOURCE_DIR}/${test_name}.comp)
    endif()
endfunction()

function(new_test test_name)
    if(${ARGC} EQUAL "1")
        get_property(is_comp TARGET ${test_name} PROPERTY compartment SET)
        get_deps(${test_name} deps_var)
        if(is_comp)
            add_test(NAME ${test_name}
                     COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.py
                             $<TARGET_FILE:manager_caller>
                             --test-args $<TARGET_FILE_NAME:${test_name}>
                             --dependencies ${deps_var}
                     COMMAND_EXPAND_LISTS)
        else()
            add_test(NAME ${test_name}
                     COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.py
                             $<TARGET_FILE_NAME:${test_name}>
                             --dependencies ${deps_var}
                     COMMAND_EXPAND_LISTS)
        endif()
    elseif(${ARGC} GREATER_EQUAL "3")
        set(test_bin ${ARGV1})
        list(JOIN ARGV2 " " test_args)
        get_property(is_comp TARGET ${test_bin} PROPERTY compartment SET)
        get_deps(${test_bin} deps_var)
        if(is_comp)
            add_test(NAME ${test_name}
                COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.py
                        $<TARGET_FILE:manager_arg_passer>
                        --test-args $<TARGET_FILE_NAME:${test_bin}> ${test_args}
                        --dependencies ${deps_var}
                COMMAND_EXPAND_LISTS)
        else()
            message(FATAL_ERROR "Shouldn't get here")
        endif()
    else()
        message(FATAL_ERROR "Missing arguments to test.")
    endif()
endfunction()

function(new_dependency target dep_file)
    set_property(TARGET ${target} APPEND PROPERTY extra_deps ${dep_file})
endfunction()

# Library tests
set(func_binaries
    "test_map"
    "test_map_multi"
    "test_ddc_overwrite"

    #"test_args_near_unmapped"
    #"test_two_comps"
    #"test_two_comps_inter_call"
    )

set(comp_binaries
    "simple"
    "simple_call_external"
    "simple_call_internal"
    "simple_call_internal_static"
    "simple_call_internal_weak"
    "simple_const_thrloc_var"
    "simple_environ"
    "simple_external"
    "simple_fopen"
    "simple_fputs"
    "simple_global_var"
    "simple_global_var-external"
    "simple_libc"
    "simple_malloc"
    "simple_open_write"
    "simple_fprintf"
    "simple_printf"
    "simple_static_var"
    "simple_static_var-external"
    "simple_syscall_getpid"
    "simple_syscall_write"
    "simple_thrloc_var"
    "simple_thrloc_var-external"
    "simple_time"
    "simple_toupper"
    "simple_va_args"
    "tls_check"
    "tls_check-external1"
    "tls_check-external2"

    "simple_malloc_saturate"
    "fail_random_access"

    "lua_simple"
    "lua_script"
    "lua_suite_some"
    "lua_script_selector"

    "args_simple"
    #"test_two_comps-comp1"
    #"test_two_comps-comp2 0x2000000"
    )

set(tests
    "simple"
    "simple_call_external"
    "simple_call_internal"
    "simple_call_internal_static"
    "simple_call_internal_weak"
    "simple_const_thrloc_var"
    "simple_environ"
    "simple_fopen"
    "simple_fputs"
    "simple_global_var"
    "simple_libc"
    "simple_malloc"
    "simple_open_write"
    "simple_fprintf"
    "simple_printf"
    "simple_static_var"
    "simple_syscall_getpid"
    "simple_syscall_write"
    "simple_thrloc_var"
    "simple_time"
    "simple_toupper"
    "simple_va_args"
    "tls_check"

    "simple_malloc_saturate"
    "fail_random_access"

    "lua_simple"
    "lua_script"
    #"lua_suite_some"

    "test_map"
    "test_map_multi"
    "test_ddc_overwrite"

    "args-simple args_simple check_simple 40 2"
    "args-more args_simple check_simple 40 2 2 2" # Check additional arguments are ignored
    "args-combined args_simple check_combined 400 2 20"
    "args-negative args_simple check_negative -42"
    "args-long-max args_simple check_llong_max 9223372036854775807"
    "args-long-min args_simple check_llong_min -9223372036854775808"
    "args-ulong-max args_simple check_ullong_max 18446744073709551615"

    "lua_script_hello lua_script do_script_hello"
    "lua_script_memtest lua_script do_script_memtest"
    )

set(tests_fail
    "simple_malloc_saturate@Memory saturated."
    "fail_random_access@Caught SIGPROT"
    "lua_script_memtest@Caught SIGPROT"
)

# Build targets
foreach(comp_t IN LISTS comp_binaries)
    string(FIND ${comp_t} " " space_pos)
    if(${space_pos} EQUAL -1)
        new_comp_test(${comp_t} TRUE)
    else()
        string(SUBSTRING ${comp_t} 0 ${space_pos} tgt_name)
        string(SUBSTRING ${comp_t} ${space_pos} -1 img_base)
        string(STRIP ${img_base} img_base)
        new_comp_test(${tgt_name} TRUE ${img_base})
    endif()
endforeach()

foreach(func_t IN LISTS func_binaries)
    new_func_test(${func_t} FALSE)
endforeach()

# Additional dependencies
target_link_libraries(simple_call_external PRIVATE simple_external)
new_dependency(simple_call_external $<TARGET_FILE:simple_external>)

target_link_libraries(simple_static_var PRIVATE simple_static_var-external)
new_dependency(simple_static_var $<TARGET_FILE:simple_static_var-external>)

target_link_libraries(simple_global_var PRIVATE simple_global_var-external)
new_dependency(simple_global_var $<TARGET_FILE:simple_global_var-external>)

target_link_libraries(simple_thrloc_var PRIVATE simple_thrloc_var-external)
new_dependency(simple_thrloc_var $<TARGET_FILE:simple_thrloc_var-external>)

target_link_libraries(tls_check PRIVATE tls_check-external1 tls_check-external2)
new_dependency(tls_check $<TARGET_FILE:tls_check-external1>)
new_dependency(tls_check $<TARGET_FILE:tls_check-external2>)

new_dependency(test_map $<TARGET_FILE:simple>)

new_dependency(lua_script ${CMAKE_CURRENT_SOURCE_DIR}/hello_world.lua)
new_dependency(lua_script ${CMAKE_CURRENT_SOURCE_DIR}/memtest.lua)

# Prepare tests
foreach(test_t IN LISTS tests)
    string(REPLACE " " ";" test_t_list ${test_t})
    list(LENGTH test_t_list test_t_len)
    if(${test_t_len} EQUAL "1")
        new_test(${test_t})
    else()
        list(GET test_t_list 0 test_name)
        list(GET test_t_list 1 test_bin)
        list(SUBLIST test_t_list 2 -1 test_args)
        new_test(${test_name} ${test_bin} "${test_args}")
    endif()
endforeach()

foreach(test_t IN LISTS tests_fail)
    string(FIND ${test_t} "@" delim_pos)
    string(SUBSTRING ${test_t} 0 ${delim_pos} test_name)
    string(SUBSTRING ${test_t} ${delim_pos} -1 pass_regex)
    string(SUBSTRING ${pass_regex} 1 -1 pass_regex)
    set_property(TEST ${test_name} PROPERTY PASS_REGULAR_EXPRESSION ${pass_regex})
endforeach()
