#!/usr/bin/bash

# Adds the address range IP_PREFIX.IP_START - IP_PREFIX_IP_END
# as secondary addresses to INTERFACE

IP_PREFIX="10.3.10"
IP_START=151
IP_END=190
INTERFACE="ens6"
SUBNET=24

for ((i=IP_START; i<=$IP_END;i++))
do
    ip addr add "$IP_PREFIX.$i/$SUBNET" dev $INTERFACE
done
