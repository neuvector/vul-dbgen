#!/bin/bash

echo "==> Making dbgen"
sleep 10000
make || exit $?
NVD_KEY=$NVD_KEY ./dbgen -v $VULN_VER

