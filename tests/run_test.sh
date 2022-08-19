#!/bin/bash

set -x
set -e

# CheriBSD setup
CHERIBSD_PORT=10086
CHERIBSD_USER=root
CHERIBSD_HOST=localhost
CHERIBSD_TEST_DIR=./testing

# Testing variables
wrapper_name="./hwwrap"
test_name=$2
test_args=$3

if [ $1 == "comp" ]
then
    scp -o "StrictHostKeyChecking no" -P $CHERIBSD_PORT $test_name $CHERIBSD_USER@$CHERIBSD_HOST:${CHERIBSD_TEST_DIR}/
    ssh -o "StrictHostKeyChecking no" -p $CHERIBSD_PORT $CHERIBSD_USER@$CHERIBSD_HOST -t "cd ${CHERIBSD_TEST_DIR} && $wrapper_name ./$(basename $test_name) $test_args"
elif [ $1 == "test" ]
then
    scp -o "StrictHostKeyChecking no" -P $CHERIBSD_PORT $test_name $CHERIBSD_USER@$CHERIBSD_HOST:${CHERIBSD_TEST_DIR}/
    ssh -o "StrictHostKeyChecking no" -p $CHERIBSD_PORT $CHERIBSD_USER@$CHERIBSD_HOST -t "cd ${CHERIBSD_TEST_DIR} && ./$(basename $test_name)"
elif [ $1 == "prep" ]
then
    FILES_TO_PREP=(./tests/hwwrap ../tests/hello_world.lua)
    ssh -o "StrictHostKeyChecking no" -p $CHERIBSD_PORT $CHERIBSD_USER@$CHERIBSD_HOST -t "mkdir -p ${CHERIBSD_TEST_DIR}"
    scp -o "StrictHostKeyChecking no" -P $CHERIBSD_PORT ${FILES_TO_PREP[@]} $CHERIBSD_USER@$CHERIBSD_HOST:${CHERIBSD_TEST_DIR}/
else
    echo "Unsupported operation given: $1. Expected [ prep, test, comp ]."
    exit 1
fi
