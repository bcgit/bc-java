
if ! [ -x "$(command -v openjdk_9)" ]; then
    JAVA_9=/usr/lib/jvm/java-9.0.4-oracle-x64
  else
    JAVA_9=`openjdk_9`
fi

if ! [ -x "$(command -v openjdk_11)" ]; then
    JAVA_11=/usr/lib/jvm/java-11-openjdk-amd64
  else
    JAVA_11=`openjdk_11`
fi

if ! [ -x "$(command -v openjdk_15)" ]; then
    JAVA_15=/usr/lib/jvm/java-15-openjdk-amd64
  else
    JAVA_15=`openjdk_15`
fi

export JAVA_9
export JAVA_11
export JAVA_15


echo "Java 9 ---> $JAVA_9"
echo "Java 11 ---> $JAVA_11"
echo "java 15 --->  $JAVA_15"

export JAVA_HOME=$JAVA_9
export PATH="$JAVA_HOME/bin:$PATH"

if [ $# -ne 1 ]
then
   echo "usage: add_module.sh prov|prov-ext|util|tls|pg|pkix|mail|jmail"
   exit 0
fi 

for jarName in bc$1-jdk18on-*.jar
do

rm -rf module.tmp

# Java 9 Step
(
    export JAVA_HOME=$JAVA_9
    export PATH="$JAVA_HOME/bin:$PATH"

    mkdir -p module.tmp/v5
    mkdir -p module.tmp/versions/v9
    mkdir -p module.tmp/versions/v11
    ( cd module.tmp/v5; jar xf ../../build/artifacts/jdk1.8/jars/$jarName )

    provJar=`echo build/artifacts/jdk1.8/jars/bcprov-jdk18on*.jar`
    utilJar=`echo build/artifacts/jdk1.8/jars/bcutil-jdk18on*.jar`
    pkixJar=`echo build/artifacts/jdk1.8/jars/bcpkix-jdk18on*.jar`
    if [ $1 = "prov" ]
    then
	javac -target 1.9 -classpath module.tmp/v5 -d module.tmp/v9 `find $1/src/main/jdk1.9 -name "*.java"` -sourcepath $1/src/main/jdk1.9:$1/src/main/java:core/src/main/java
	$JAVA_11/bin/javac -classpath module.tmp/v5 -d module.tmp/v11 `find $1/src/main/jdk1.11 -name "*.java"` -sourcepath $1/src/main/jdk1.11:$1/src/main/java:core/src/main/java
	$JAVA_15/bin/javac -classpath module.tmp/v5:module.tmp/v11 -d module.tmp/v15 `find prov/src/main/jdk1.15 -name "*.java"` -sourcepath prov/src/main/jdk1.15:prov/src/main/jdk1.11:prov/src/main/java:core/src/main/java
    elif [ $1 = "prov-ext" ]
    then
	javac -target 1.9 -classpath module.tmp/v5 -d module.tmp/v9 `find prov/src/main/ext-jdk1.9 -name "*.java"` -sourcepath prov/src/main/ext-jdk1.9:prov/src/main/java:core/src/main/java
	$JAVA_11/bin/javac -classpath module.tmp/v5 -d module.tmp/v11 `find prov/src/main/jdk1.11 -name "*.java"` -sourcepath prov/src/main/jdk1.11:prov/src/main/java:core/src/main/java
	$JAVA_15/bin/javac -classpath module.tmp/v5:module.tmp/v11 -d module.tmp/v15 `find prov/src/main/jdk1.15 -name "*.java"` -sourcepath prov/src/main/jdk1.15:prov/src/main/jdk1.11:prov/src/main/java:core/src/main/java
    elif [ $1 = "mail" ]
    then
	javac  -target 1.9 --module-path ${provJar}:$utilJar:$pkixJar -classpath module.tmp/v5 -d module.tmp/v9 `find $1/src/main/jdk1.9 -name "*.java"` -sourcepath $1/src/main/jdk1.9:$1/src/main/java
    elif [ $1 = "jmail" ]
    then
        ( cd build/artifacts/jdk1.8/bcjmail-jdk18on-*; mkdir src; cd src; unzip ../src.zip )
        jmailSrc=`echo build/artifacts/jdk1.8/bcjmail-jdk18on-*/src/`
	javac  -target 1.9 --module-path ${provJar}:$utilJar:$pkixJar:libs/jakarta.mail-2.0.1.jar:libs/jakarta.activation-api-2.0.0.jar -classpath module.tmp/v5 -d module.tmp/v9 `find $1/src/main/jdk1.9 -name "*.java"` -sourcepath $1/src/main/jdk1.9:$jmailSrc
        rm -r build/artifacts/jdk1.8/bcjmail-jdk18on-*/src
    elif [ $1 = "pkix" ]
    then
	javac  -target 1.9 --module-path ${provJar}:$utilJar -classpath module.tmp/v5 -d module.tmp/v9 `find $1/src/main/jdk1.9 -name "*.java"` -sourcepath $1/src/main/jdk1.9:$1/src/main/java
    elif [ $1 = "tls" ]
    then
	javac  -target 1.9 --module-path ${provJar}:$utilJar -classpath module.tmp/v5 -d module.tmp/v9 `find $1/src/main/jdk1.9 -name "*.java"` -sourcepath $1/src/main/jdk1.9:$1/src/main/java
    else
	javac  -target 1.9 --module-path $provJar -classpath module.tmp/v5 -d module.tmp/v9 `find $1/src/main/jdk1.9 -name "*.java"` -sourcepath $1/src/main/jdk1.9:$1/src/main/java
    fi
)
# Java 11 Step
(
    export JAVA_HOME=$JAVA_11
    export "PATH=$JAVA_HOME/bin:$PATH"

    cd module.tmp
    if [ -d v11 ]
    then
        extras=`2>&1 jar cf $jarName -C v5 . --release 9 -C v9 . --release 11 -C v11 . | egrep Warning | sed -e "s/Warning: entry //" | sed -e "s/ contains.*$//"`
    else
        extras=`2>&1 jar cf $jarName -C v5 . --release 9 -C v9 . | egrep Warning | sed -e "s/Warning: entry //" | sed -e "s/ contains.*$//"`
    fi
    for f in `echo $extras`
    do
	p=`echo $f | sed -e "s:META-INF/versions/9::"`
	rm v9/$p
    done
)


if ! [ -x "$(command -v ./bnd.sh)" ]; then
echo "WARNING: Skipping running bnd.sh"
else
sh ./bnd.sh build/artifacts/jdk1.8/jars/$jarName
fi

cp build/artifacts/jdk1.8/jars/$jarName module.tmp/$jarName
# Java 11 Step
(
    export JAVA_HOME=$JAVA_11
    export PATH="$JAVA_HOME/bin:$PATH"

    cd module.tmp
    jar uf $jarName --release 9 -C v9 .
    if [ -d v11 ]
    then
        jar uf $jarName --release 11 -C v11 .
    fi
)
# Java 15 Step
(
    export JAVA_HOME=$JAVA_15
    export PATH="$JAVA_HOME/bin:$PATH"

    cd module.tmp
    if [ -d v15 ]
    then
        jar uf $jarName --release 15 -C v15 .
    fi
)
cp module.tmp/$jarName build/artifacts/jdk1.8/jars/$jarName


if ! [ -x "$(command -v bcsign11)" ]; then
echo "WARNING: Skipping  bcsign11"
else
bcsign11 build/artifacts/jdk1.8/jars/$jarName
fi


done
