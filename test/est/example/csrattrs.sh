#!/usr/bin/env bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $DIR/../../../
BCDIR=`pwd`
popd

$DIR/ensurejar.sh

CP="$DIR/jars/pkix.jar:$DIR/jars/bcprov.jar:$DIR/jars/test.jar:$DIR/jars/bctls.jar"
java -classpath $CP org.bouncycastle.test.est.examples.CSRAttributesExample --sl $DIR/jars/suffixlist.dat $@

