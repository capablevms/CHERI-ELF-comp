# CHERI ELF compartmentalisation

An approach to provide compartmentalisation to user-code in a hybrid CHERI
environment.

### Overview

The idea is to provide a library with an API to allow user-code to be
compartmentalized with respect to data. This means that when we enter a
compartment, we expect to not be able to read or write from memory that is not
associated with that compartment. This is achieved via the default data
capability (`DDC`) register.

Eventual desired functionality:
* load a binary, identifying appropriate entry points
* execute a loaded binary, given a previously identified valid entry point
* inter-compartment communication, either via capabilities, or shared memory

#### Executing a compartment

TODO
* transitioning into a compartment, ensuring no data is leaked, and state is
  consistent;
* inter-compartment communication;
* transitioning out of a compartment, returning some required result.

#### Function interception

Not all functions within a compartment can be executed with a restrained `DDC`.
For example, `vDSO` functions would not have access to the `vDSO` page
dynamically loaded against the manager, and memory management functions are not
aware of the limited space allocated to a compartment for scratch memory. As
such, we *intercept* these functions, in order to execute them with higher
privilege (i.e., unbound `DDC`), and in a controlled fashion. This involves
patching each intercepted function with code to perform a transition into the
manager (at the same time unbounding the `DDC`), performing the associated
function, then transitioning back into the compartment.

#### Limitations (and sort-of main TODO list)

Current limitations (as this is a work in progress, some of these are planned
to be addressed):
* single compartment;
* the user-code must be compiled with `--static` and `--image-base` set to some
  pre-determined variable;
* entry point of the compartment is via `main`, and no parameters are
  supported.
