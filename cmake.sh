#!/bin/bash

NPROCS="$(getconf _NPROCESSORS_ONLN)"

cmake -S . -B build/

cd build/ && make -j $NPROCS
