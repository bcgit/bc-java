#!/bin/sh

JAVA_HOME=/opt/jdk1.5.0
export JAVA_HOME

PATH=$JAVA_HOME/bin:$PATH
export PATH

for jarFile in $*
do
    base=`basename $jarFile .jar`
    javaVersion=`echo $base | sed -e "s/.*\(jdk..\).*/\\1/"`
    name=`echo $base | sed -e "s/\([^-]*\)-jdk.*/\\1/"`
    bcVersion=`echo $base | sed -e "s/$name-${javaVersion}.*-\(1.*\)/\\1/" | sed -e "s/b/.0./"`
    baseVersion=`echo $bcVersion | sed -e "s/[^.]*.\([0-9]*\).*/\\1/"`
    bcMaxVersion="`expr "${baseVersion}" "+" "1"`"
 
    if [ "`echo $bcVersion | fgrep b`" = "$bcVersion" ]
    then
        bcVersion=`echo $bcVersion | sed -e "s/50b/49./"`
    fi

    if `echo $jarFile | fgrep bcprov > /dev/null`
    then
        cat > /tmp/bnd.props <<%
Bundle-Version: $bcVersion
Bundle-Name: $name
Bundle-SymbolicName: $name
Bundle-RequiredExecutionEnvironment: J2SE-1.5
Export-Package: org.bouncycastle.*;version=$bcVersion
Import-Package: *;resolution:=optional
%
    else
        cat > /tmp/bnd.props <<%
Bundle-Version: $bcVersion
Bundle-Name: $name
Bundle-SymbolicName: $name
Bundle-RequiredExecutionEnvironment: J2SE-1.5
Export-Package: org.bouncycastle.*;version=$bcVersion
Import-Package: org.bouncycastle.*;version="[${bcVersion},1.${bcMaxVersion})",*;resolution:=optional
%
    fi

    java -jar $BND_HOME/biz.aQute.bnd-2.2.0.jar wrap --properties /tmp/bnd.props $jarFile
    mv $base.jar $jarFile
done
