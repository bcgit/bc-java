#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

set -e

java -cp $DIR/../test/build/libs/*:$DIR/../core/build/libs/* org.bouncycastle.test.qtesla.QTESLAVectorTest "$@"
