#!/bin/bash

set -e

#
# This script is for running inside the docker container
#

cd /workspace/bc-java
source ci/common.sh

export BC_JDK8=`openjdk_8`
export BC_JDK11=`openjdk_11`
export BC_JDK17=`openjdk_17`
export BC_JDK21=`openjdk_21`


export JAVA_HOME=`openjdk_21`
export PATH=$JAVA_HOME/bin:$PATH

./gradlew -stacktrace clean build




