#!/bin/bash

echo "==> Making dbgen"
make || exit $?
./dbgen -v $VULN_VER -nvd_key $NVD_KEY
