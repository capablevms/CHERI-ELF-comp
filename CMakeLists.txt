cmake_minimum_required(VERSION 3.6)
project(lua_test)

set(TEST_DIR ${CMAKE_SOURCE_DIR}/tests)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

set(LUA_DIR ${CMAKE_SOURCE_DIR}/third_party/lua)
set(LUA_INSTALL_DIR ${LUA_DIR}/install)

# Build lua
#add_custom_target(
    #lua
    #COMMAND make && make local
    #WORKING_DIRECTORY ${LUA_DIR}
#)

add_subdirectory(${SRC_DIR})
add_subdirectory(${TEST_DIR})
