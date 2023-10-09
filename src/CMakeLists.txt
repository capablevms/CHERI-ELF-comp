# Compartment management library
add_library(chcomp STATIC
    manager.c
    mem_mng.c
    compartment.c
    intercept.c
    transition.S
    )
target_include_directories(chcomp PRIVATE ${INCLUDE_DIR} ${TOML_INCLUDE_DIR})
target_link_libraries(chcomp PRIVATE tomllib)
