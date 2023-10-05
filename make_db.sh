#!/bin/bash

echo "==> Making dbgen"
make || exit $?
NVD_KEY=$NVD_KEY ./dbgen -v $VULN_VER