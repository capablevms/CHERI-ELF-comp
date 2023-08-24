#!/usr/bin/env python3
import argparse
import pathlib

from fabric import Connection

################################################################################
# Constants
################################################################################

CHERIBSD_PORT = 10086
CHERIBSD_USER = "root"
CHERIBSD_HOST = "localhost"
CHERIBSD_TEST_DIR = "./testing"

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

def exec_cmd(conn, cmd):
    conn.run(cmd, echo = True)

################################################################################
# Main
################################################################################

vm_conn = Connection(host = CHERIBSD_HOST, user = CHERIBSD_USER, port = CHERIBSD_PORT)
exec_cmd(vm_conn, f'mkdir -p {CHERIBSD_TEST_DIR}')
file_deps = [args.test, *args.dependencies]
for dep in file_deps:
    put_file(vm_conn, dep)
exec_cmd(vm_conn, f'cd {CHERIBSD_TEST_DIR} && ./{args.test.name} {" ".join(args.test_args)}')
vm_conn.close()
