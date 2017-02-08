#!/usr/bin/env bash
set -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ ! -d "$DIR/jars" ]; then
    mkdir $DIR/jars

pushd $DIR/../../../
BCDIR=`pwd`
popd

pushd $DIR/jars

if  type curl > /dev/null; then
    curl -O https://downloads.bouncycastle.org/betas/bcprov-jdk15on-157b03.jar
elif type wget > /dev/null ; then
    wget https://downloads.bouncycastle.org/betas/bcprov-jdk15on-157b03.jar
else
    echo "No wget or curl to download provider jar"
fi

popd

cd $BCDIR

gradle -x test clean jar

cp $BCDIR/test/build/libs/* $DIR/jars
cp $BCDIR/pkix/build/libs/*.jar $DIR/jars

fi



