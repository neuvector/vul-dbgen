#!/bin/bash

echo "==> Making dbgen"
make || exit $?
./dbgen -v $VULN_VER
