# Compartment management library
add_library(chcomp STATIC
    manager.c
    compartment.c
    intercept.c
    transition.S
    )
target_include_directories(chcomp PRIVATE ${INCLUDE_DIR} ${TOML_INCLUDE_DIR})
target_link_libraries(chcomp PRIVATE tomllib)

add_library(computils SHARED
    comp_utils.c)
target_include_directories(computils PRIVATE ${INCLUDE_DIR})
