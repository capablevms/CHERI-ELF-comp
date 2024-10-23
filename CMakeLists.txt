cmake_minimum_required(VERSION 3.16)
project(CHERI_ELF_Compartments LANGUAGES C ASM)

# Set global compilation options
add_compile_options(-pedantic -Wextra -Wno-gnu-binary-literal -Wno-language-extension-token $<$<CONFIG:Debug>:-Werror>)

# Set useful directory variables
set(TEST_DIR ${CMAKE_SOURCE_DIR}/tests)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

# Build lua
set(LUA_DIR ${CMAKE_SOURCE_DIR}/third-party/lua)
set(LUA_INSTALL_DIR ${LUA_DIR})
set(LUA_LIB_PATH ${LUA_DIR}/liblua.so)
set(LUA_INCLUDE_DIR ${LUA_DIR})

add_custom_command(
    OUTPUT ${LUA_LIB_PATH}
    COMMAND make
    WORKING_DIRECTORY ${LUA_DIR}
)

add_custom_target(
    lua
    DEPENDS ${LUA_LIB_PATH}
)
add_library(lualib STATIC IMPORTED)
add_dependencies(lualib lua)
set_target_properties(lualib
    PROPERTIES
    IMPORTED_LOCATION ${LUA_LIB_PATH}
)

# Build tomlc99
set(TOML_DIR ${CMAKE_SOURCE_DIR}/third-party/tomlc99)
set(TOML_INSTALL_DIR ${TOML_DIR}/build)
set(TOML_LIB_PATH ${TOML_INSTALL_DIR}/lib/libtoml.a)
set(TOML_INCLUDE_DIR ${TOML_INSTALL_DIR}/include)

add_custom_command(
    OUTPUT ${TOML_LIB_PATH}
    COMMAND make install prefix=${TOML_INSTALL_DIR}
    WORKING_DIRECTORY ${TOML_DIR}
)

add_custom_target(
    toml
    DEPENDS ${TOML_LIB_PATH}
)
add_library(tomllib STATIC IMPORTED)
add_dependencies(tomllib toml)
set_target_properties(tomllib
    PROPERTIES
    IMPORTED_LOCATION ${TOML_LIB_PATH}
)

# Build tommyds
set(TOMMYDS_DIR ${CMAKE_SOURCE_DIR}/third-party/tommyds/tommyds)
set(TOMMYDS_LIB ${CMAKE_SOURCE_DIR}/third-party/tommyds/tommyds/libtommyds.a)

add_custom_command(
    OUTPUT ${TOMMYDS_LIB}
    COMMAND make
    WORKING_DIRECTORY ${TOMMYDS_DIR}
)

add_custom_target(
    tommyds
    DEPENDS ${TOMMYDS_LIB}
)
add_library(tommydslib STATIC IMPORTED)
add_dependencies(tommydslib tommyds)
set_target_properties(tommydslib
    PROPERTIES
    IMPORTED_LOCATION ${TOMMYDS_LIB}
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
