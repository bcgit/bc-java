#!/bin/sh

artifactsHome=build/artifacts/jdk1.8/jars

testJar="$artifactsHome/bctest-jdk18on-173b02.jar";

rm -rf mtest
mkdir mtest

cp $artifactsHome/*.jar mtest/

rm mtest/bcjmail-*
rm mtest/bcprov-ext-*
rm mtest/bctest-*

a=(`jar -tf "$testJar" | grep -E "AllTests\.class" | sed -e 's!.class!!' | sed -e 's|/|.|g'`);



echo $testJar

for i in "${a[@]}"
do
  echo $i

  case $i in org\.bouncycastle\.pqc\.legacy\.*)
   echo "skipping $i"
   continue
  esac


   java --module-path ./mtest/ \
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
   --add-reads org.bouncycastle.mail=ALL-UNNAMED \
   --add-exports org.bouncycastle.provider/org.bouncycastle.internal.asn1.cms=ALL-UNNAMED \
   --add-exports org.bouncycastle.provider/org.bouncycastle.internal.asn1.bsi=ALL-UNNAMED \
   --add-exports org.bouncycastle.provider/org.bouncycastle.internal.asn1.eac=ALL-UNNAMED \
   -cp "$testJar:libs/junit.jar:libs/mail.jar:libs/activation.jar" \
   -Dbc.test.data.home=core/src/test/data \
    $i
    echo "-------------------------------------"
    echo ""
done




#  java --module-path `pwd` \
#   --illegal-access=warn \
#   --add-modules org.bouncycastle.pg \
#   --add-exports org.bouncycastle.pg/org.bouncycastle.gpg.test=junit \
#   --add-exports org.bouncycastle.pg/org.bouncycastle.openpgp.test=junit \
#   --add-exports org.bouncycastle.pg/org.bouncycastle.openpgp.examples.test=junit \
#   --add-reads org.bouncycastle.pg=ALL-UNNAMED \
#   --patch-module org.bouncycastle.pg=../$1:../$2 \
#    $i