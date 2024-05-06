#!/bin/bash
set -e

if ! command -v osgiscanner &> /dev/null
then
    echo "osgiscanner not on path"
    exit 1
fi

export script_loc=$( cd -- "$( dirname -- "$0" )" &> /dev/null && pwd )
cd $script_loc

export BCHOME=`pwd`

osgiscanner -f osgi_scan.xml
