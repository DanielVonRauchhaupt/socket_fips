#!/usr/bin/env python3
from socket import socket, AF_INET, SOCK_DGRAM
from typing import List

UDP_IP = "127.0.0.1" # specify the destination IP address here
UDP_PORT = 8080 # specify the destination port here
MESSAGE = "B" # specify the payload here

print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT)
print("message:", MESSAGE)

client_iprange = [f"127.0.0.{i}" for i in range(2,255)]

socks : List[socket] = []

for ip in client_iprange:
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind((ip,0))
    socks.append(sock)

for _ in range(1):
    for sock in socks:
        sock.sendto(MESSAGE.encode('utf-8'),(UDP_IP,UDP_PORT)) 
