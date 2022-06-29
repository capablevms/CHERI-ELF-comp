# Compartment management library
add_library(chcomp STATIC
    manager.c
    mem_mng.c
    compartment.c
    transition.S
    )
target_include_directories(chcomp PRIVATE ${INCLUDE_DIR})
