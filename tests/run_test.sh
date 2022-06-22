#!/bin/bash

set -x
set -e

if [ $# -ne 1 ]
then
    echo "Expected one parameter: path to executable."
    exit 1
fi

CHERIBSD_PORT=10086
CHERIBSD_USER=root
CHERIBSD_HOST=localhost

scp -o "StrictHostKeyChecking no" -P $CHERIBSD_PORT $1 $CHERIBSD_USER@$CHERIBSD_HOST:
ssh -o "StrictHostKeyChecking no" -p $CHERIBSD_PORT $CHERIBSD_USER@$CHERIBSD_HOST -t ./$(basename $1)
