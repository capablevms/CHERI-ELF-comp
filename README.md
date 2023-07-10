# CHERI ELF compartmentalisation

An approach to provide compartmentalisation to user-code in a hybrid CHERI
environment.

## Overview

The idea is to provide a library with an API to allow user-code to be
compartmentalized with respect to data. This means that when we enter a
compartment, we expect to not be able to read or write from memory that is not
associated with that compartment. This is achieved via the default data
capability (`DDC`) register.

Eventual desired functionality:
* load a binary, identifying appropriate entry points
* execute a loaded binary, given a previously identified valid entry point
* inter-compartment communication, either via capabilities, or shared memory

### High-level idea

This project provides an API for managing compartments. Users can write
programs with this API, which allows them to define compartments for a given
ELF binary. Each compartment will be restricted to its own memory chunk, and
should not be able to access (i.e., load or store) any memory outside the chunk
determined by the manager.

Compartments are loaded from a file on disk, in the form of a pre-compiled
static ELF binary. We prefer static binaries, as this ensures (most) of the
compartment functionality is self contained (further discussion on exceptions
[in this Section](#function-interception)). Compartments are then allocated a
chunk of the manager process' memory, and the executable code of the
compartment is loaded inside that chunk. Additional memory is reserved within
the chunk for the compartment's stack and heap. A capability is defined around
the allocated chunk. Whenever we transition to a given compartment, we load its
respective capability inside the DDC, essentially limiting memory loads and
stores within the compartment's allocated memory region. Once the compartment
is loaded into memory, we are able to call functions defined in the binary from
the manager.

There is one exception when a compartment may access memory outside its
designated region: if it is passed a capability by another compartment, then
that capability may be used to access memory defined by the capability, which
originally would be exclusively owned by the other compartment. This would be
useful for sharing more complex data across compartments, but doing so
essentially removes the security over the shared region for the original owner
compartment, so must be done so sparsely.

### Executing a compartment

TODO
* transitioning into a compartment, ensuring no data is leaked, and state is
  consistent;
* inter-compartment communication;
* transitioning out of a compartment, returning some required result;
* defining compartment entry points.

### Function interception

Not all functions within a compartment can be executed with a restrained `DDC`.
For example, `vDSO` functions would not have access to the `vDSO` page
dynamically loaded against the manager, and memory management functions are not
aware of the limited space allocated to a compartment for scratch memory. As
such, we *intercept* these functions, in order to execute them with higher
privilege (i.e., unbound `DDC`), and in a controlled fashion. This involves
patching each intercepted function with code to perform a transition into the
manager (at the same time unbounding the `DDC`), performing the associated
function, then transitioning back into the compartment.

### Limitations (and sort-of main TODO list)

Current limitations (as this is a work in progress, some of these are planned
to be addressed):
* single compartment;
* the user-code must be compiled with `--static` and `--image-base` set to some
  pre-determined variable;
* only 3 arguments supported for argument passing, not floats or pointers.
