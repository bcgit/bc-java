#!/bin/bash

set -e

#
# This script is for running inside the docker container
#

cd /workspace/bc-java
source ci/common.sh

export BC_JDK8=`openjdk_8`
export BC_JDK11=`openjdk_11`
export BC_JDK15=`openjdk_15`
export BC_JDK17=`openjdk_17`
export BC_JDK21=`openjdk_21`

export JAVA_HOME=`openjdk_17`
export PATH=$JAVA_HOME/bin:$PATH

# Checkstyle
./gradlew check -x test;


# OSGI scanner only, no testing
./gradlew clean build -x test
./osgi_scan.sh

