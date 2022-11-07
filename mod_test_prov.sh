#!/bin/sh

if ! [ -x "$(command -v openjdk_11)" ]; then
    JAVA_11=/usr/lib/jvm/java-11-openjdk-amd64
  else
    JAVA_11=`openjdk_11`
fi


export JAVA_HOME=$JAVA_11

artifactsHome=build/artifacts/jdk1.8/jars

tj=( $artifactsHome/bctest-jdk18on-*.jar )

testJar="${tj[0]}";

rm -rf mtest
mkdir mtest

cp $artifactsHome/*.jar mtest/

rm mtest/bcjmail-*
rm mtest/bcprov-ext-*
rm mtest/bctest-*


for j in mtest/*.jar; do
jar -tf $j | grep module-info\.class >> /dev/null

if [[ $? != 0 ]]; then
    echo "$j is missing module-info"
    exit 1;
else
     echo "$j is has module-info"
fi

done


a=(`$JAVA_HOME/bin/jar -tf "$testJar" | grep -E "AllTests\.class" | sed -e 's!.class!!' | sed -e 's|/|.|g'`);


echo $testJar

for i in "${a[@]}"
do
  echo $i

  case $i in org\.bouncycastle\.pqc\.legacy\.*)
   echo "skipping $i"
   continue
  esac


   $JAVA_HOME/bin/java --module-path ./mtest/ \
   --add-modules org.bouncycastle.mail \
   --add-modules org.bouncycastle.pg \
   --add-modules org.bouncycastle.pkix \
   --add-modules org.bouncycastle.provider \
   --add-modules org.bouncycastle.tls \
   --add-modules org.bouncycastle.util \
   --add-opens org.bouncycastle.provider/org.bouncycastle.jcajce.provider.symmetric=ALL-UNNAMED \
   --add-opens org.bouncycastle.provider/org.bouncycastle.jcajce.provider.digest=ALL-UNNAMED \
   --add-opens org.bouncycastle.util/org.bouncycastle.asn1.cmc=ALL-UNNAMED \
   --add-opens org.bouncycastle.util/org.bouncycastle.oer.its.etsi102941.basetypes=ALL-UNNAMED \
   --add-opens org.bouncycastle.util/org.bouncycastle.oer.its.etsi102941=ALL-UNNAMED \
   --add-opens org.bouncycastle.util/org.bouncycastle.oer.its.ieee1609dot2dot1=ALL-UNNAMED \
   --add-opens org.bouncycastle.util/org.bouncycastle.oer.its.etsi103097.extension=ALL-UNNAMED \
   --add-opens org.bouncycastle.util/org.bouncycastle.oer.its.etsi103097=ALL-UNNAMED \
   --add-opens org.bouncycastle.util/org.bouncycastle.oer.its.ieee1609dot2.basetypes=ALL-UNNAMED \
   --add-opens org.bouncycastle.util/org.bouncycastle.oer.its.ieee1609dot2=ALL-UNNAMED \
   --add-opens org.bouncycastle.pkix/org.bouncycastle.tsp=ALL-UNNAMED \
   --add-reads org.bouncycastle.mail=ALL-UNNAMED \
   --add-reads org.bouncycastle.provider=ALL-UNNAMED \
   --add-exports org.bouncycastle.provider/org.bouncycastle.internal.asn1.cms=ALL-UNNAMED \
   --add-exports org.bouncycastle.provider/org.bouncycastle.internal.asn1.bsi=ALL-UNNAMED \
   --add-exports org.bouncycastle.provider/org.bouncycastle.internal.asn1.eac=ALL-UNNAMED \
   -cp "$testJar:libs/junit.jar:libs/mail.jar:libs/activation.jar" \
   -Dbc.test.data.home=core/src/test/data \
    $i

    if [[ $? != 0 ]]; then
            echo ""
            echo "--------------------------------!!!"
            echo "$i failed"
            exit 1;
    fi

    echo "-------------------------------------"
    echo ""
done


