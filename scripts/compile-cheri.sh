#!/bin/bash
set -e
set -x

# CheriBSD
export CC=/home/cheriworker/cheri/output/morello-sdk/bin/clang
export AR=/home/cheriworker/cheri/output/morello-sdk/bin/llvm-ar
export CFLAGS="--config cheribsd-morello-hybrid.cfg -DARM -O0"
export ASMFLAGS="--config cheribsd-morello-hybrid.cfg"
export LDFLAGS="--config cheribsd-morello-hybrid.cfg"

# Morello Linux Glibc
#export CC=/home/cheriworker/morello-glibc/arm-gnu-toolchain-10.1.morello-alp2-x86_64-aarch64-none-linux-gnu/bin/aarch64-none-linux-gnu-gcc
#export AR=/home/cheriworker/morello-glibc/arm-gnu-toolchain-10.1.morello-alp2-x86_64-aarch64-none-linux-gnu/bin/aarch64-none-linux-gnu-ar
#export CFLAGS="-march=morello"
#export ASMFLAGS="-march=morello"
#export LDFLAGS="-march=morello"

# Morello Linux

#export CC=clang
#export CFLAGS="-DX86"

build_dir="$(pwd)/build"
src_dir="$(pwd)/"

cmake \
	-G Ninja \
	-DCMAKE_BUILD_TYPE=DEBUG \
	-B $build_dir \
	-S $src_dir
cmake --build $build_dir -v
