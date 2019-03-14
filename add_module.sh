export JAVA_HOME=/usr/lib/jvm/java-9-oracle
export PATH=$JAVA_HOME/bin:$PATH

if [ $# -ne 1 ]
then
   echo "usage: add_module.sh prov|tls|pg|pkix|mail"
   exit 0
fi 

if [ $1 = "prov" ]
then
    for jarName in bc$1-jdk15on-*.jar
    do
        rm -rf module.tmp
        mkdir -p module.tmp/META-INF/versions/9

        cp build/artifacts/jdk1.5/jars/$jarName module.tmp
        cd module.tmp
        jar xf $jarName

        javac --module-path ../build/artifacts/jdk1.5/jars/bcprov-jdk15on*.jar -classpath . -d META-INF/versions/9 ../$1/src/main/jdk1.9/module-info.java -sourcepath ../$1/src/main/jdk1.9:../$1/src/main/java:../core/src/main/java

        jar cfm $jarName META-INF/MANIFEST.MF META-INF org
        cd ..
        cp module.tmp/$jarName build/artifacts/jdk1.5/jars/$jarName
    done

    for jarName in bc$1-ext-jdk15on-*.jar
    do
        rm -rf module.tmp
        mkdir -p module.tmp/META-INF/versions/9

        cp build/artifacts/jdk1.5/jars/$jarName module.tmp
        cd module.tmp
        jar xf $jarName

        javac --module-path ../build/artifacts/jdk1.5/jars/bcprov-jdk15on*.jar -classpath . -d META-INF/versions/9 ../$1/src/main/ext-jdk1.9/module-info.java -sourcepath ../$1/src/main/ext-jdk1.9:../$1/src/main/java:../core/src/main/java

        jar cfm $jarName META-INF/MANIFEST.MF META-INF org
        cd ..
        cp module.tmp/$jarName build/artifacts/jdk1.5/jars/$jarName
    done
else
    for jarName in bc$1-jdk15on-*.jar
    do
        rm -rf module.tmp
        mkdir -p module.tmp/META-INF/versions/9
    
        cp build/artifacts/jdk1.5/jars/$jarName module.tmp
        cd module.tmp
        jar xf $jarName
    
        provJar=`echo ../build/artifacts/jdk1.5/jars/bcprov-jdk15on*.jar`
        pkixJar=`echo ../build/artifacts/jdk1.5/jars/bcpkix-jdk15on*.jar`

        if [ $1 = "mail" ]
        then
            javac --module-path $provJar:$pkixJar -classpath . -d META-INF/versions/9 ../$1/src/main/jdk1.9/module-info.java -sourcepath ../$1/src/main/jdk1.9:../$1/src/main/java
        else
            javac --module-path $provJar -classpath . -d META-INF/versions/9 ../$1/src/main/jdk1.9/module-info.java -sourcepath ../$1/src/main/jdk1.9:../$1/src/main/java
        fi

    
        jar cfm $jarName META-INF/MANIFEST.MF META-INF org
        cd ..
        cp module.tmp/$jarName build/artifacts/jdk1.5/jars/$jarName
    done
fi
