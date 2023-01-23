#!/bin/bash

NPROCS="$(getconf _NPROCESSORS_ONLN)"

cmake -S . -B build/ -DCMAKE_BUILD_TYPE=Debug

cd build/ && make -j $NPROCS
