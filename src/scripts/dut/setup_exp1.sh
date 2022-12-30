#!/bin/bash

# Empties logfiles and reloads ebpf programm

#Paths to logfiles
SVR_LOG='/mnt/scratch/PR/udpsvr.log'
FAIL2BAN_LOG='/mnt/scratch/Miko/logs/fail2ban.log'
BIND_LOG='/mnt/scratch/Miko/logs/bind/bind-rate.log'
NGINX_LOG='/mnt/scratch/Miko/logs/error.log'

#Paths to binaries
EBPF_LOADER='/root/PR/ebpf_loader'
SVR='/root/PR/server'

#Clear logfiles
for LOG in $SVR_LOG $FAIL2BAN_LOG $BIND_LOG $NGINX_LOG; do
    truncate -s 0 $LOG
done

# Load ebf programm and start server
$EBPF_LOADER ens6 --reload
#$SVR&
