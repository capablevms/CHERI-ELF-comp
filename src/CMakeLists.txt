# Compartment management library
add_library(chcomp STATIC
    compartment.c
    intercept.c
    manager.c
    symbols_comp.c
    symbols_lib.c
    transition.S
    )
target_include_directories(chcomp PRIVATE ${INCLUDE_DIR} ${TOML_INCLUDE_DIR})
target_link_libraries(chcomp PRIVATE tomllib)

add_library(computils SHARED
    comp_utils.c)
target_include_directories(computils PRIVATE ${INCLUDE_DIR})
