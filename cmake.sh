#!/bin/bash

NPROCS="$(getconf _NPROCESSORS_ONLN)"

cmake -S . -B build/ -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=1

cd build/ && make -j $NPROCS
