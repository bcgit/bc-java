#!/usr/bin/env bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ "$1" = "force" ]; then
    rm -Rf $DIR/jars
fi


if [ ! -d "$DIR/jars" ]; then
    mkdir $DIR/jars

pushd $DIR/../../../
BCDIR=`pwd`
popd

pushd $DIR/jars

if  type curl > /dev/null; then
    curl -o bcprov.jar  https://downloads.bouncycastle.org/betas/bcprov-jdk15on-157b11.jar
    curl -o bctls.jar https://downloads.bouncycastle.org/betas/bctls-jdk15on-157b11.jar
elif type wget > /dev/null ; then
    wget -O bcprov.jar https://downloads.bouncycastle.org/betas/bcprov-jdk15on-157b11.jar
    wget -O bctls.jar https://downloads.bouncycastle.org/betas/bctls-jdk15on-157b11.jar
else
    echo "No wget or curl to download provider jar"
fi


popd

cd $BCDIR

gradle test:updateSuffixes
gradle -x test clean jar

cp $BCDIR/test/build/libs/test-*.jar $DIR/jars/test.jar
cp $BCDIR/pkix/build/libs/bcpkix-*.jar $DIR/jars/pkix.jar

fi



