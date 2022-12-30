#!/bin/bash

TREX_PATH='/mnt/scratch/Miko/trex-core/scripts/'
CORE_COUNT=16

if (($# > 0))
then
    cd $TREX_PATH && ./t-rex-64 -i -c $CORE_COUNT $1
else 
    cd $TREX_PATH && ./t-rex-64 -i -c $CORE_COUNT
fi
