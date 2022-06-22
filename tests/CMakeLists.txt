# WIP

add_executable(hwwrap
    ${TEST_DIR}/hello_world_comps.c
    )
target_include_directories(hwwrap PUBLIC ${INCLUDE_DIR})
target_link_libraries(hwwrap PUBLIC chcomp)

add_executable(lua-simple
    ${TEST_DIR}/lua_simple.c
    )
add_dependencies(lua-simple lualib)
target_link_libraries(lua-simple lualib dl m)
target_include_directories(lua-simple PUBLIC ${LUA_INCLUDE_DIR})
target_compile_options(lua-simple PUBLIC -static) # -fPIE -pie
target_link_options(lua-simple PUBLIC -static "LINKER:-image-base=0x1000000") # -fPIE -ie

# Library tests

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

new_proj_test(simple TRUE)
new_proj_test(test_map FALSE)
