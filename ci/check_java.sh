#!/bin/bash

set -e

#
# This script is for running inside the docker container
#

cd /workspace/bc-java
source ci/common.sh



export JAVA_HOME=`openjdk_25`
export PATH=$JAVA_HOME/bin:$PATH

# Checkstyle
./gradlew clean build check -x test;


# OSGI scanner only, no testing
./osgi_scan.sh


# module tester
./run_mtt.sh