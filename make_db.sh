#!/bin/bash

echo "==> Making dbgen"
go build || exit $?
./dbgen -v $VULN_VER
