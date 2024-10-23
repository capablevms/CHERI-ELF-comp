#!/bin/sh

if [ $# -ne 1 ]
then
    echo "Expected exactly one argument: test to execute!"
    exit 1
fi

EXECUTE_COUNT=${EXECUTE_COUNT:=100}

for i in $(seq 1 $EXECUTE_COUNT)
do
    ./$1
done
