#!/bin/bash

set -e

export script_loc=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
version=$(fgrep version "$script_loc/gradle.properties"  | sed -e "s/version=//")

echo ""
echo "Module dependency testing"
echo ""

#
# This is an internal tool used to verify that classes needed by one module
# are correctly exported by another module.
#

levels=( "9" "11" "17" "21" "25" )

for level in "${levels[@]}"
do
echo "---------------------------------------------------------------------"
echo "Start ${level}"

(
  echo "With Jakarta mail.."
  modtest \
  -scan "${script_loc}/jmail/build/libs/bcjmail-jdk18on-${version}.jar" \
  -scan "${script_loc}/mls/build/libs/bcmls-jdk18on-${version}.jar" \
  -scan "${script_loc}/pg/build/libs/bcpg-jdk18on-${version}.jar" \
  -scan "${script_loc}/pkix/build/libs/bcpkix-jdk18on-${version}.jar" \
  -scan "${script_loc}/prov/build/libs/bcprov-jdk18on-${version}.jar" \
  -scan "${script_loc}/tls/build/libs/bctls-jdk18on-${version}.jar" \
  -scan "${script_loc}/util/build/libs/bcutil-jdk18on-${version}.jar" \
  -include "^org\.bouncycastle\..*" \
  -ignore "^java\..*" \
  -ignore "^javax\..*" \
  -ignore "^jakarta\..*" \
  -ignore "^io\.grpc\..*" \
  -ignore "^com\.google\..*" \
  -ignore "^com\.sun\..*" \
  -jvmlevel ${level}
)

( # mail
  echo "With Java mail.."
  modtest \
  -scan "${script_loc}/mail/build/libs/bcmail-jdk18on-${version}.jar" \
  -scan "${script_loc}/mls/build/libs/bcmls-jdk18on-${version}.jar" \
  -scan "${script_loc}/pg/build/libs/bcpg-jdk18on-${version}.jar" \
  -scan "${script_loc}/pkix/build/libs/bcpkix-jdk18on-${version}.jar" \
  -scan "${script_loc}/prov/build/libs/bcprov-jdk18on-${version}.jar" \
  -scan "${script_loc}/tls/build/libs/bctls-jdk18on-${version}.jar" \
  -scan "${script_loc}/util/build/libs/bcutil-jdk18on-${version}.jar" \
  -include "^org\.bouncycastle\..*" \
  -ignore "^java\..*" \
  -ignore "^javax\..*" \
  -ignore "^jakarta\..*" \
  -ignore "^io\.grpc\..*" \
  -ignore "^com\.google\..*" \
  -ignore "^com\.sun\..*" \
  -jvmlevel ${level}
)
  echo "End java ${level}"
  echo ""
done