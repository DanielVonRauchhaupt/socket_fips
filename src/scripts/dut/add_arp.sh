#!/bin/bash

# Finds the MAC Address of the target ip and adds
# the address range IP_PREFIX.IP_START - IP_PREFIX.IP_END
# to the arp table, mapping to the MAC of the target

TARGET_IPADDR="10.3.10.132"
ETHER_ADDR=$(arp -a | grep $TARGET_IPADDR | cut -d ' ' -f4)
IP_PREFIX="10.3.10"
IP_START=151
IP_END=190

for ((i=IP_START;i<=IP_END;i++))
do
    arp -n -s "$IP_PREFIX.$i" $ETHER_ADDR
done 
