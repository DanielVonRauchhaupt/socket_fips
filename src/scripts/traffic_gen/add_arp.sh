#!/bin/bash 

# Finds MAC address of TARGET_IPADDR and adds address range
# IP_PREFIX.IP_START - IP_PREFIX.IP_END to arp table, mapping
# to MAC of target

TARGET_IPADDR="10.3.10.131"
ETHER_ADDR=$(arp -a | grep $TARGET_IPADDR | cut -d ' ' -f4)
IP_PREFIX="10.3.10"
IP_START=201
IP_END=240

for ((i=$IP_START;i<=$IP_END;i++)) 
do
    arp -s "$IP_PREFIX.$i" $ETHER_ADDR
done 
