export JAVA_HOME=/usr/lib/jvm/java-9-oracle
#export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64/
export PATH=$JAVA_HOME/bin:$PATH

if [ $# -ne 1 ]
then
   echo "usage: add_module.sh prov|prov-ext|tls|pg|pkix|mail"
   exit 0
fi 

for jarName in bc$1-jdk15on-*.jar
do

rm -rf module.tmp

# Java 9 Step
(
    export JAVA_HOME=/usr/lib/jvm/java-9-oracle
    export PATH=$JAVA_HOME/bin:$PATH

    mkdir -p module.tmp/v5
    mkdir -p module.tmp/versions/v9
    ( cd module.tmp/v5; jar xf ../../build/artifacts/jdk1.5/jars/$jarName )

    provJar=`echo build/artifacts/jdk1.5/jars/bcprov-jdk15on*.jar`
    pkixJar=`echo build/artifacts/jdk1.5/jars/bcpkix-jdk15on*.jar`
    if [ $1 = "prov" ]
    then
	javac -target 1.9 -classpath module.tmp/v5 -d module.tmp/v9 `find $1/src/main/jdk1.9 -name "*.java"` -sourcepath $1/src/main/jdk1.9:$1/src/main/java:core/src/main/java
    elif [ $1 = "prov-ext" ]
    then
	javac -target 1.9 -classpath module.tmp/v5 -d module.tmp/v9 `find prov/src/main/ext-jdk1.9 -name "*.java"` -sourcepath prov/src/main/ext-jdk1.9:prov/src/main/java:core/src/main/java
    elif [ $1 = "mail" ]
    then
	javac  -target 1.9 --module-path ${provJar}:$pkixJar -classpath module.tmp/v5 -d module.tmp/v9 `find $1/src/main/jdk1.9 -name "*.java"` -sourcepath $1/src/main/jdk1.9:$1/src/main/java
    else
	javac  -target 1.9 --module-path $provJar -classpath module.tmp/v5 -d module.tmp/v9 `find $1/src/main/jdk1.9 -name "*.java"` -sourcepath $1/src/main/jdk1.9:$1/src/main/java
    fi
)
# Java 11 Step
(
    export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
    export PATH=$JAVA_HOME/bin:$PATH 

    cd module.tmp
    extras=`2>&1 jar cf $jarName -C v5 . --release 9 -C v9 . | egrep Warning | sed -e "s/Warning: entry //" | sed -e "s/ contains.*$//"`
    for f in `echo $extras`
    do
	p=`echo $f | sed -e "s:META-INF/versions/9::"`
	rm v9/$p
    done
)
sh ./bnd.sh build/artifacts/jdk1.5/jars/$jarName
cp build/artifacts/jdk1.5/jars/$jarName module.tmp/$jarName
# Java 11 Step
(
    export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
    export PATH=$JAVA_HOME/bin:$PATH 

    cd module.tmp
    jar uf $jarName --release 9 -C v9 .
)
cp module.tmp/$jarName build/artifacts/jdk1.5/jars/$jarName

bcsign build/artifacts/jdk1.5/jars/$jarName
done
