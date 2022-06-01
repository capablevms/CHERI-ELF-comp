# Executable - producer_consumer_test
#add_executable(test
    #producer_consumer.c
    #producer_consumer_mem.c
    #)

#target_link_directories(test PUBLIC ${LUA_INSTALL_DIR}/lib)
#target_link_libraries(test ${LUA_INSTALL_DIR}/lib/liblua.a dl m)
#target_include_directories(test PUBLIC ${LUA_INSTALL_DIR}/include)
#add_dependencies(test lua)

# Executable - hello_world_elf
#add_library(hwelf STATIC
#    ${TEST_DIR}/hello_world_elf.c
#    )
#target_compile_options(hwelf PUBLIC -static)
#set_property(TARGET hwelf PROPERTY POSITION_INDEPENDENT_CODE ON)

#add_executable(hwelf-exe-pie
    #${TEST_DIR}/hello_world_elf.c
    #)
#target_compile_options(hwelf-exe-pie PUBLIC -static) # -fPIE -pie
#target_link_options(hwelf-exe-pie PUBLIC -static) # -fPIE -ie
#set_property(TARGET hwelf-exe-pie PROPERTY POSITION_INDEPENDENT_CODE ON)

add_executable(hwwrap
    ${TEST_DIR}/hello_world_comps.c
    ${SRC_DIR}/compartment.c
    ${SRC_DIR}/manager.c
    ${SRC_DIR}/mem_mng.c
    )
target_include_directories(hwwrap PUBLIC ${INCLUDE_DIR})

add_executable(simple
    ${TEST_DIR}/simple.c
    )
target_compile_options(simple PUBLIC -static) # -fPIE -pie
target_link_options(simple PUBLIC -static "LINKER:-image-base=0x1000000") # -fPIE -ie

add_executable(simple2
    ${TEST_DIR}/simple2.c
    )
target_compile_options(simple2 PUBLIC -static) # -fPIE -pie
target_link_options(simple2 PUBLIC -static "LINKER:--wrap=__vdso_gettimeofday" ) # -fPIE -ie

add_executable(lua-simple
    ${TEST_DIR}/lua_simple.c
    )
target_link_directories(lua-simple PUBLIC ${LUA_INSTALL_DIR}/lib)
target_link_libraries(lua-simple ${LUA_INSTALL_DIR}/lib/liblua.a dl m)
target_include_directories(lua-simple PUBLIC ${LUA_INSTALL_DIR}/include)
target_compile_options(lua-simple PUBLIC -static) # -fPIE -pie
target_link_options(lua-simple PUBLIC -static "LINKER:-image-base=0x1000000") # -fPIE -ie
#add_dependencies(lua-simple lua)
