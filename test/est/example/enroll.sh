#!/usr/bin/env bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $DIR/../../../
BCDIR=`pwd`
popd
CP="$BCDIR/pkix/build/libs/bcpkix-jdk15on-1.56-SNAPSHOT.jar:$BCDIR/test/build/libs/test-1.56-SNAPSHOT.jar:$BCDIR/prov/build/libs/prov-1.56-SNAPSHOT.jar:$BCDIR/core/build/libs/core-1.56-SNAPSHOT.jar"
java -cp $CP org.bouncycastle.test.est.examples.EnrollExample $@

