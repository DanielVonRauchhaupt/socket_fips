#!/bin/bash

PREFIX=/mnt/scratch

truncate -s 0 $PREFIX/Miko/logs/bind/bind-rate.log
truncate -s 0 $PREFIX/Miko/logs/fail2ban.log
truncate -s 0 $PREFIX/PR/logs/udpsvr.log
