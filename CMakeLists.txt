cmake_minimum_required(VERSION 3.6)
project(CHERI_ELF_Compartments LANGUAGES C ASM)

set(TEST_DIR ${CMAKE_SOURCE_DIR}/tests)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

# Build lua
set(LUA_DIR ${CMAKE_SOURCE_DIR}/third-party/lua)
set(LUA_INSTALL_DIR ${LUA_DIR}/install)

add_custom_command(
    OUTPUT ${LUA_INSTALL_DIR}/lib/liblua.a
    COMMAND make && make local
    WORKING_DIRECTORY ${LUA_DIR}
)

add_custom_target(
    lua
    DEPENDS ${LUA_INSTALL_DIR}/lib/liblua.a
)
add_library(lualib STATIC IMPORTED GLOBAL)
add_dependencies(lualib lua)
set_target_properties(lualib
    PROPERTIES
    IMPORTED_LOCATION ${LUA_INSTALL_DIR}/lib/liblua.a
)

# Build sources
add_subdirectory(${SRC_DIR})

# Build tests
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)
endif()

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
    add_subdirectory(${TEST_DIR})
endif()
