#!/usr/bin/env python3

import datetime
import os
import shlex
import subprocess
import sys

from fabric import Connection

################################################################################
# Constants
################################################################################

guard_getenv = lambda envname: os.getenv(envname) or sys.exit(f"Missing env var `{envname}`!")
BENCH_HOST = guard_getenv("COMP_BENCH_HOST")
BENCH_USER = guard_getenv("COMP_BENCH_USER")

BENCH_RUN_PATH = "/home/0152la/bench-script"
BENCH_RUN_LIBS_PATH = f"{BENCH_RUN_PATH}/libs"

SRC_DIR = os.getcwd()
BUILD_DIR = f"{SRC_DIR}/build-release"
BUILD_TESTS_DIR = f"{BUILD_DIR}/tests"
SRC_TESTS_DIR = f"{SRC_DIR}/tests"
SCRIPTS_DIR = f"{SRC_DIR}/scripts"
RESULTS_DIR = f"{BUILD_DIR}/results-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"

THIRD_PARTY_DIR = f"{SRC_DIR}/third-party"
LUA_DIR = f"{THIRD_PARTY_DIR}/lua"

CMAKE_BUILD_ENV = {
        **os.environ,
        "CC": "/home/cheriworker/cheri/output/morello-sdk/bin/clang",
        "AR": "/home/cheriworker/cheri/output/morello-sdk/bin/llvm-ar",
        "CFLAGS": "--config cheribsd-morello-hybrid.cfg -DARM -O3",
        "ASMFLAGS": "--config cheribsd-morello-hybrid.cfg",
        "LDFLAGS": "--config cheribsd-morello-hybrid.cfg"
        }

BENCH_RUN_ENV = {
        "COMP_LIBRARY_PATH": f"{BENCH_RUN_PATH}/libs",
        "LD_64_LIBRARY_PATH": f"{BENCH_RUN_PATH}/libs",
        "EXECUTE_COUNT": 1000,
        }

TESTS = [
        "lua_script"
        ]

LOCAL_LIBS = [
        f"{THIRD_PARTY_DIR}/lua/liblua.so",
        f"{BUILD_DIR}/src/libcomputils.so",
        ]
REMOTE_LIBS = [
               "/usr/lib64/libc.so.7",
               "/usr/lib64/libdl.so.1",
               "/usr/lib64/libm.so.5",
               ]

BENCH_BINS = [
        f"{SCRIPTS_DIR}/multi_execute.sh",
        f"{BUILD_TESTS_DIR}/manager_call_multi",
        f"{SRC_TESTS_DIR}/hello_world.lua"
        ]
BENCH_EXECUTIONS = {
        "native_multi": "multi_execute.sh ./lua_script",
        "manager_multi": "manager_call_multi ./lua_script.so",
        }

################################################################################
# Helper functions
################################################################################

def remote_put(conn, file, dest):
    conn.put(file, remote = dest)

def remote_exec(conn, cmd, env = None, out = None):
    return conn.run(cmd, env = env, echo = True, warn = True)

def remote_exec_log(conn, cmd, env, out):
    return conn.run(cmd, env = env, echo = True, warn = True, out_stream = out, hide = 'stdout')

def remote_exec_log_err(conn, cmd, env, out):
    return conn.run(cmd, env = env, echo = True, warn = True, err_stream = out, hide = 'stdout')

################################################################################
# Main
################################################################################


# Compile project
cmake_cmd = f"cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -B {BUILD_DIR} -S {SRC_DIR}"
subprocess.run(shlex.split(cmake_cmd), env = CMAKE_BUILD_ENV)
cmake_cmd = f"cmake --build {BUILD_DIR}"
subprocess.run(shlex.split(cmake_cmd), env = CMAKE_BUILD_ENV)

# Compile native tests
native_build_flags = f"-I{LUA_DIR} -L{LUA_DIR} -llua"
native_build_cmd = f"{CMAKE_BUILD_ENV['CC']} {CMAKE_BUILD_ENV['CFLAGS']} -o {BUILD_TESTS_DIR}/{{0}} {SRC_TESTS_DIR}/{{0}}.c {native_build_flags}"
for test in TESTS:
    cmd = shlex.split(native_build_cmd.format(test))
    subprocess.run(cmd)

# Prepare results folder
os.makedirs(RESULTS_DIR, exist_ok = True)

# Copy tests and scripts
conn = Connection(host = BENCH_HOST, user = BENCH_USER, inline_ssh_env = True)
remote_exec(conn, f"mkdir -p {BENCH_RUN_LIBS_PATH}")

for test in TESTS:
    remote_put(conn, f"{BUILD_TESTS_DIR}/{test}", BENCH_RUN_PATH)
    remote_put(conn, f"{BUILD_TESTS_DIR}/{test}.so", BENCH_RUN_PATH)
for bbin in BENCH_BINS:
    remote_put(conn, bbin, BENCH_RUN_PATH)
for llib in LOCAL_LIBS:
    remote_put(conn, llib, BENCH_RUN_LIBS_PATH)
for rlib in REMOTE_LIBS:
    remote_exec(conn, f"ln -sf {rlib} {BENCH_RUN_LIBS_PATH}")

# Execute benchmarks
for key, cmd in BENCH_EXECUTIONS.items():
    cmd = f"cd {BENCH_RUN_PATH} ; truss -c ./{cmd}"
    with open(f"{RESULTS_DIR}/truss-{key}", 'w') as res_fd:
        remote_exec_log_err(conn, cmd, env = BENCH_RUN_ENV, out = res_fd)

cmd = f"cd {BENCH_RUN_PATH} ; hyperfine"
cmd = ' '.join([cmd, *[f"'./{x}'" for x in BENCH_EXECUTIONS.values()]])
with open(f"{RESULTS_DIR}/hyperfine", 'w') as res_fd:
    remote_exec_log(conn, cmd, env = BENCH_RUN_ENV, out = res_fd)

conn.close()
