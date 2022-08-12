# Loader executable

add_executable(hwwrap
    ${TEST_DIR}/hello_world_comps.c
    )
target_include_directories(hwwrap PUBLIC ${INCLUDE_DIR})
target_link_libraries(hwwrap PUBLIC chcomp)

# Library test functions

function(new_proj_test test_name compartment)
    add_executable(${test_name}
        ${test_name}.c)
    target_link_libraries(${test_name} PRIVATE chcomp)
    target_include_directories(${test_name} PRIVATE ${INCLUDE_DIR})
    if(${compartment})
        target_compile_options(${test_name} PRIVATE -static)
        target_link_options(${test_name} PRIVATE -static "LINKER:-image-base=0x1000000")
    endif()
    add_test(NAME ${test_name}
             COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.sh $<TARGET_FILE:${test_name}>)
endfunction()

function(new_proj_lua_test test_name)
    add_executable(${test_name}
        ${test_name}.c)
    add_dependencies(${test_name} lualib)
    target_link_libraries(${test_name} PRIVATE lualib dl m)
    target_include_directories(${test_name} PRIVATE ${LUA_INCLUDE_DIR})
    target_compile_options(${test_name} PRIVATE -static)
    target_link_options(${test_name} PRIVATE -static "LINKER:-image-base=0x1000000")
    add_test(NAME ${test_name}
             COMMAND ${CMAKE_SOURCE_DIR}/tests/run_test.sh $<TARGET_FILE:${test_name}> ${ARGV2})
endfunction()

# Library tests

new_proj_test(simple TRUE)
new_proj_test(time TRUE)

new_proj_test(test_map FALSE)

new_proj_lua_test(lua_simple)
new_proj_lua_test(lua_script ${TEST_DIR}/hello_world.lua)
