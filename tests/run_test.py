#!/usr/bin/env python3
import argparse
import pathlib
import os

from fabric import Connection

################################################################################
# Constants
################################################################################

CHERIBSD_PORT = 10086
CHERIBSD_USER = "root"
CHERIBSD_HOST = "localhost"

CHERIBSD_TEST_DIR = "testing"
COMP_LIBRARY_PATH = "testing/libs"

################################################################################
# Arguments
################################################################################

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('test', type=pathlib.Path,
    help='Path to main test file to be ran')
arg_parser.add_argument('--test-args', nargs='*', default = [],
    help='Arguments to be passed to the test file')
arg_parser.add_argument('--dependencies', nargs='*', default = [], type=pathlib.Path,
    help='File dependencies for the given test')
args = arg_parser.parse_args()

################################################################################
# Helper functions
################################################################################

def put_file(conn, src_file):
    conn.put(src_file, remote = f'{CHERIBSD_TEST_DIR}/')

def exec_cmd(conn, cmd, remote_env):
    return conn.run(cmd, env = remote_env, echo = True)

################################################################################
# Main
################################################################################

vm_conn = Connection(host = CHERIBSD_HOST, user = CHERIBSD_USER, port = CHERIBSD_PORT)

home_dir = vm_conn.run("echo $HOME", hide = True).stdout.strip()
CHERIBSD_TEST_DIR = os.path.join(home_dir, CHERIBSD_TEST_DIR)
COMP_LIBRARY_PATH = os.path.join(home_dir, COMP_LIBRARY_PATH)
remote_env = {
        'COMP_LIBRARY_PATH': COMP_LIBRARY_PATH,
        'LD_LIBRARY_PATH': COMP_LIBRARY_PATH,
        }

file_deps = [args.test, *args.dependencies]
for dep in file_deps:
    put_file(vm_conn, dep)
exec_cmd(vm_conn, f'cd {CHERIBSD_TEST_DIR} ; ./{args.test.name} {" ".join(args.test_args)}', remote_env)
vm_conn.close()
