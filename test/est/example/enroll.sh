#!/usr/bin/env bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $DIR/../../../
BCDIR=`pwd`
popd

$DIR/ensurejar.sh

CP="$DIR/jars/bcpkix-jdk15on-1.56-SNAPSHOT.jar:$DIR/jars/bcprov-jdk15on-157b03.jar:$DIR/jars/test-1.56-SNAPSHOT.jar"
java -classpath $CP org.bouncycastle.test.est.examples.EnrollExample $@
