cmake_minimum_required(VERSION 3.6)
project(CHERI_ELF_Compartments LANGUAGES C ASM)

set(TEST_DIR ${CMAKE_SOURCE_DIR}/tests)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

set(LUA_DIR ${CMAKE_SOURCE_DIR}/third_party/lua)
set(LUA_INSTALL_DIR ${LUA_DIR}/install)

# TODO double check this works from scratch
# Build lua
#add_custom_target(
    #lua
    #COMMAND make && make local
    #WORKING_DIRECTORY ${LUA_DIR}
#)

add_subdirectory(${SRC_DIR})

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(${TEST_DIR})
endif()
