#!/usr/bin/env python3
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

LOCAL_LIBS = [
        "./third-party/lua/liblua.so",
        "./build/src/libcomputils.so"
        ]
REMOTE_LIBS = [
        "/lib/libc.so.7",
        "/usr/lib/libdl.so.1",
        "/lib/libm.so.5",
        ]

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

vm_conn.run(f'mkdir -p {CHERIBSD_TEST_DIR}')
vm_conn.run(f'mkdir -p {COMP_LIBRARY_PATH}')
for lib in LOCAL_LIBS:
    vm_conn.put(lib, remote = f'{COMP_LIBRARY_PATH}', )
for lib in REMOTE_LIBS:
    cmd = f'cd {COMP_LIBRARY_PATH} ; ln -s {lib}'
    vm_conn.run(cmd)
vm_conn.close()
