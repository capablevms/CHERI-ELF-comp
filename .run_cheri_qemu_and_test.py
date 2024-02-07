#!/usr/bin/env python3

# Adapted from
# https://github.com/capablevms/cheri-examples/blob/master/tests/run_cheri_examples.py

import argparse
import importlib.util
import os
import subprocess
import sys

from pathlib import Path

# Emulate `sys.path` from path of module `run_tests_common` (found via
# environment variable `PYTHONPATH`), as required by the CHERI testing
# infrastructure which we are using to simplify booting a QEMU instance
test_scripts_dir = str(Path(importlib.util.find_spec("run_tests_common").origin).parent.absolute())
sys.path = sys.path[sys.path.index(test_scripts_dir):]

from run_tests_common import boot_cheribsd, run_tests_main

def run_tests(qemu: boot_cheribsd.QemuCheriBSDInstance, args: argparse.Namespace) -> bool:
    if args.sysroot_dir is not None:
        boot_cheribsd.set_ld_library_path_with_sysroot(qemu)
    boot_cheribsd.info("Running tests for CHERI-ELF-compartments")

    # Test environment setup
    subprocess.run(["./tests/init_test.py"], check = True)

    # Run command on host to test the executed client
    os.chdir(f"{args.build_dir}/build")
    subprocess.run(["ctest", "--output-on-failure"], check = True)
    return True

if __name__ == '__main__':
    # This call has the side-effect of booting a QEMU instance
    run_tests_main(test_function=run_tests, need_ssh=True, should_mount_builddir=False)
