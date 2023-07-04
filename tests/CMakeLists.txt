# Loader executable

add_executable(hwwrap
    ${TEST_DIR}/hello_world_comps.c
    )
target_include_directories(hwwrap PUBLIC ${INCLUDE_DIR})
target_link_libraries(hwwrap PUBLIC chcomp)

# Library test functions

function(new_proj_test test_name compartment)
    string(FIND ${test_name} " " test_name_delim_pos)
    if (NOT ${test_name_delim_pos} EQUAL "-1")
        string(SUBSTRING ${test_name} ${test_name_delim_pos} "-1" test_args)
        string(SUBSTRING ${test_name} "0" ${test_name_delim_pos} test_name)
    endif()
    add_executable(${test_name}
        ${test_name}.c)
    target_link_libraries(${test_name} PRIVATE chcomp lualib dl m)
    target_include_directories(${test_name} PRIVATE ${INCLUDE_DIR} ${LUA_INCLUDE_DIR})
    if(${compartment})
        target_compile_options(${test_name} PRIVATE -static)
        target_link_options(${test_name} PRIVATE -static "LINKER:-image-base=0x1000000")
        add_test(NAME ${test_name}
                 COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.sh comp $<TARGET_FILE:${test_name}> ${test_args})
    else()
        add_test(NAME ${test_name}
                 COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.sh test $<TARGET_FILE:${test_name}>)
    endif()
endfunction()

# Library tests
set(func_tests
    "test_map"
    )

set(comp_tests
    "simple"
    "time"
    "lua_simple"
    "lua_script"
    )

foreach(comp_t IN LISTS comp_tests)
    new_proj_test(${comp_t} TRUE)
endforeach()

foreach(func_t IN LISTS func_tests)
    new_proj_test(${func_t} FALSE)
endforeach()

