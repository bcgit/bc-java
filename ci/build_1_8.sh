#!/bin/bash
set -e

#
# This script is for running inside the docker container
#

cd /workspace/bc-java
source ci/common.sh

export JAVA_HOME=`openjdk_8`
export export PATH=$JAVA_HOME/bin:$PATH
export JDKPATH=$JAVA_HOME

export PATH=$PATH:`ant-bin-1-10`

sh build1-8+