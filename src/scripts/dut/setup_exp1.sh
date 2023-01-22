#!/bin/bash

# Empties logfiles and reloads ebpf programm

#Paths to logfiles
SVR_LOG='/mnt/scratch/PR/logs/udpsvr.log'
FAIL2BAN_LOG='/mnt/scratch/Miko/logs/fail2ban.log'
BIND_LOG='/mnt/scratch/Miko/logs/bind/bind-rate.log'
NGINX_LOG='/mnt/scratch/Miko/logs/error.log'

#Paths to binaries
EBPF_LOADER='/mnt/scratch/PR/bachelorarbeit/src/bin/ebpf_loader'

#Clear logfiles
for LOG in $SVR_LOG $FAIL2BAN_LOG $BIND_LOG $NGINX_LOG; do
    truncate -s 0 $LOG
done

# Load ebf programm and start server
$EBPF_LOADER enp24s0f0np0 --reload
#$SVR&
