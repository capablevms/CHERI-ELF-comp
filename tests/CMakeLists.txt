# Loader executable

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

# Library test functions

define_property(TARGET
                PROPERTY compartment
                BRIEF_DOCS "Whether this target is a CHERI compartment"
                FULL_DOCS "Whether this target is a CHERI compartment")

function(new_target test_name compartment)
    add_executable(${test_name}
        ${test_name}.c)
    target_link_libraries(${test_name} PRIVATE chcomp dl m)
    target_link_libraries(${test_name} PRIVATE lualib)
    target_include_directories(${test_name} PRIVATE ${INCLUDE_DIR} ${LUA_INCLUDE_DIR})
    if(${compartment})
        target_compile_options(${test_name} PRIVATE -static)
        target_link_options(${test_name} PRIVATE -static "LINKER:-image-base=0x1000000")
        set_property(TARGET ${test_name} PROPERTY compartment TRUE)
    else()
        target_link_libraries(${test_name} PRIVATE tomllib)
        target_include_directories(${test_name} PRIVATE ${TOML_INCLUDE_DIR})
    endif()
endfunction()

function(new_test test_name)
    if(${ARGC} EQUAL "1")
        get_property(is_comp TARGET ${test_name} PROPERTY compartment SET)
        if(is_comp)
            add_test(NAME ${test_name}
                     COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.sh comp $<TARGET_FILE:${test_name}>)
        else()
            add_test(NAME ${test_name}
                     COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.sh test $<TARGET_FILE:${test_name}>)
        endif()
    elseif(${ARGC} GREATER_EQUAL "3")
        set(test_bin ${ARGV1})
        list(JOIN ARGV2 " " test_args)
        message(STATUS ${test_args})
        get_property(is_comp TARGET ${test_bin} PROPERTY compartment SET)
        if(is_comp)
            add_test(NAME ${test_name}
                COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.sh comp $<TARGET_FILE:${test_bin}> ${test_args})
        else()
            message(FATAL_ERROR "Shouldn't get here")
        endif()
    else()
        message(FATAL_ERROR "Missing arguments to test.")
    endif()
endfunction()

# Library tests
set(func_binaries
    "test_map")

set(comp_binaries
    "simple"
    "time"
    "lua_simple"
    "lua_script"
    "args_simple"
    )

set(tests
    "test_map"
    "simple"
    "time"
    "lua_simple"
    "lua_script"
    "args-simple args_simple check_simple 40 2"
    "args-more args_simple check_simple 40 2 2 2" # Check additional arguments are ignored
    "args-combined args_simple check_combined 400 2 20"
    "args-negative args_simple check_negative -42"
    "args-long-max args_simple check_llong_max 9223372036854775807"
    "args-long-min args_simple check_llong_min -9223372036854775808"
    "args-ulong-max args_simple check_ullong_max 18446744073709551615"
    )

foreach(comp_t IN LISTS comp_binaries)
    new_target(${comp_t} TRUE)
endforeach()

foreach(func_t IN LISTS func_binaries)
    new_target(${func_t} FALSE)
endforeach()

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
