#!/bin/bash

set -e

build_dir="$(pwd)/build"
src_dir="$(pwd)"
cheri_dir="/home/buildbot/cheri/output"

# Update submodules
git submodule update --init

# Apply lua patch
lua_dir="$src_dir/third-party/lua"
patch -d $lua_dir -i ../lua.patch

# Apply toml patch
toml_dir="$src_dir/third_party/tomlc99"
patch -d $toml_dir -i ../toml.patch

# Build project locally
export CC=$cheri_dir/morello-sdk/bin/clang
export CFLAGS="--config cheribsd-morello-hybrid.cfg"
export ASMFLAGS="--config cheribsd-morello-hybrid.cfg"

cmake \
        -G Ninja \
        -DCMAKE_BUILD_TYPE=DEBUG \
        -DLLVM_DIR=$cheri_dir/morello-sdk/lib/cmake/llvm \
        -DClang_DIR=$cheri_dir/morello-sdk/lib/cmake/clang \
        -B $build_dir \
        -S $src_dir
cmake --build $build_dir

# Set arguments for Morello hybrid instance
export SSHPORT=10086

args=(
    --architecture morello-hybrid
    # Qemu System to use
    --qemu-cmd $cheri_dir/sdk/bin/qemu-system-morello
    --bios edk2-aarch64-code.fd
    --disk-image $cheri_dir/cheribsd-morello-hybrid.img
    # Required build-dir in CheriBSD
    --build-dir .
    --ssh-port $SSHPORT
    --ssh-key $HOME/.ssh/id_ed25519.pub
    )

# Spawn CHERI QEMU instance, then execute `ctest`
python3 $src_dir/.run_cheri_qemu_and_test.py "${args[@]}"
