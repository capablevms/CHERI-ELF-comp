#!/bin/bash

#export CC=/home/cheriworker/cheri/output/morello-sdk/bin/clang
#export AR=/home/cheriworker/cheri/output/morello-sdk/bin/llvm-ar

export CC=clang
export AR=llvm-ar-10
#export CFLAGS="-fsanitize=address"

src_dir=/home/cheriworker/workspace/CHERI-ELF-comp
build_dir=$src_dir/build-linux
third_party_dir=$src_dir/third-party
comp_libs_dir=$build_dir/libs
sys_lib=/lib/x86_64-linux-gnu

cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -B $build_dir -S $src_dir
cmake --build $build_dir --target comp_harness so_harness
cmake --build $build_dir --target lua_script simple_thrloc_var simple_const_thrloc_var simple


mkdir -p $comp_libs_dir

libs=(
	$build_dir/src/libcomputils.so 
	$third_party_dir/lua/liblua.so 
	$sys_lib/libdl.so.2 
	$sys_lib/libm.so.6 
	$sys_lib/libc.so.6 
	/lib64/ld-linux-x86-64.so.2
)
for lib in ${libs[@]}
do
	if [ -f $comp_libs_dir/$(basename $lib) ]
	then
		continue
	fi
	if [ ! -f $lib ]
	then
		echo "Did not find $lib!"
		exit
	fi
	cp $lib $comp_libs_dir
done
