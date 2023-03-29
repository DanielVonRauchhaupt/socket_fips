#!/bin/bash

# Finds the MAC Address of the target ip and adds
# the address range IP_PREFIX.IP_START - IP_PREFIX.IP_END
# to the arp table, mapping to the MAC of the target



TARGET_IPADDR="10.3.10.132"
ping $TARGET_IPADDR -c 1 -q
IP_PREFIX="10.3.11"
IP_PREFIX2="192.168"
INTERFACE=$(ip route | grep "$IP_PREFIX.*" | cut -d ' ' -f3)
ETHER_ADDR=$(ip neigh show | grep $TARGET_IPADDR | cut -d ' ' -f5)
IP_START=1
IP_END=254

# Valid ips
for ((i=IP_START;i<=IP_END;i++))
do
   ip neigh add "$IP_PREFIX.$i" lladdr $ETHER_ADDR dev $INTERFACE
done 

# Invalid ips

for((i=IP_START;i<=IP_END;i++))
do
   for ((j=IP_START;j<=IP_END;j++))
   do
      ip neigh add "$IP_PREFIX2.$j.$i" lladdr $ETHER_ADDR dev $INTERFACE
   done 
done
