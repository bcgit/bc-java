(
export JAVA_HOME=/opt/jdk-11.0.1
export PATH=$JAVA_HOME/bin:$PATH

mkdir /tmp/jakarta.test
mkdir /tmp/classes.jakarta 
(cd mail/src/test/java; tar cf - * | (cd /tmp/jakarta.test && tar xf -))
(cd mail/src/test/resources; tar cf - * | (cd /tmp/classes.jakarta && tar xf -))
(
  cd /tmp/jakarta.test/org/bouncycastle/mail/smime/test
  for i in *.java
  do
	ed $i << %%
g/javax.activation/s//jakarta.activation/g
g/javax.mail/s//jakarta.mail/g
w
q
%%
  done
)

javac -d /tmp/classes.jakarta -classpath build/artifacts/jdk1.8/jars/bcprov-jdk18on-173.jar:build/artifacts/jdk1.8/jars/bcutil-jdk18on-173.jar:build/artifacts/jdk1.8/jars/bcpkix-jdk18on-173.jar:build/artifacts/jdk1.8/jars/bcjmail-jdk18on-173.jar:/opt/junit/junit.jar:libs/jakarta.mail-2.0.1.jar:libs/jakarta.activation-api-2.0.0.jar /tmp/jakarta.test/org/bouncycastle/mail/smime/test/*.java
java -cp /tmp/classes.jakarta:build/artifacts/jdk1.8/jars/bcprov-jdk18on-173.jar:build/artifacts/jdk1.8/jars/bcpkix-jdk18on-173.jar:build/artifacts/jdk1.8/jars/bcutil-jdk18on-173.jar:build/artifacts/jdk1.8/jars/bcjmail-jdk18on-173.jar:/opt/junit/junit.jar:libs/jakarta.mail-2.0.1.jar:libs/jakarta.activation-api-2.0.0.jar:libs/activation.jar org.bouncycastle.mail.smime.test.AllTests

)

(
export JAVA_HOME=/opt/jdk-11.0.1
export PATH=$JAVA_HOME/bin:$PATH

javac -d /tmp/classes.jdk11 -classpath build/artifacts/jdk1.8/jars/bcprov-jdk18on-173.jar:/opt/junit/junit.jar prov/src/test/jdk1.11/org/bouncycastle/jcajce/provider/test/XDHKeyTest.java
java -cp /tmp/classes.jdk11:build/artifacts/jdk1.8/jars/bcprov-jdk18on-173.jar:/opt/junit/junit.jar org.bouncycastle.jcajce.provider.test.XDHKeyTest

)

(
export JAVA_HOME=/opt/jdk-15
export PATH=$JAVA_HOME/bin:$PATH

javac -d /tmp/classes.jdk15 -classpath build/artifacts/jdk1.8/jars/bcprov-jdk18on-173.jar:/opt/junit/junit.jar prov/src/test/jdk1.15/org/bouncycastle/jcajce/provider/test/EdDSA15Test.java
java -cp /tmp/classes.jdk15:build/artifacts/jdk1.8/jars/bcprov-jdk18on-173.jar:/opt/junit/junit.jar org.bouncycastle.jcajce.provider.test.EdDSA15Test
)
