#!/bin/bash

set -e

#
# This script is for running inside the docker container
#

cd /workspace/bc-java
source ci/common.sh



export JAVA_HOME=`openjdk_21`
export PATH=$JAVA_HOME/bin:$PATH


./gradlew clean build publishAllPublicationsToCwmavenRepository -x test


