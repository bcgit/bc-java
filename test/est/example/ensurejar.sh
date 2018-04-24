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

curl -o ver.index  https://downloads.bouncycastle.org/betas/index.html
bcver=`fgrep bcprov-ext ver.index | fgrep .jar | sed -e "s:^.*bcprov-ext-jdk15on-::" | sed -e "s:.jar<.*$::"`

if  type curl > /dev/null; then
    curl -o bcprov.jar  https://downloads.bouncycastle.org/betas/bcprov-jdk15on-$bcver.jar
    curl -o bctls.jar https://downloads.bouncycastle.org/betas/bctls-jdk15on-$bcver.jar
    curl -o suffixlist.dat  https://www.publicsuffix.org/list/public_suffix_list.dat
elif type wget > /dev/null ; then
    wget -O bcprov.jar https://downloads.bouncycastle.org/betas/bcprov-jdk15on-$bcver.jar
    wget -O bctls.jar https://downloads.bouncycastle.org/betas/bctls-jdk15on-$bcver.jar
    wget -O suffixlist.dat https://www.publicsuffix.org/list/public_suffix_list.dat
else
    echo "No wget or curl to download provider jar"
fi


popd

cd $BCDIR

gradle -x test clean jar

cp $BCDIR/test/build/libs/test-*.jar $DIR/jars/test.jar
cp $BCDIR/pkix/build/libs/bcpkix-*.jar $DIR/jars/pkix.jar

fi



