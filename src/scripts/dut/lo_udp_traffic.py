from scapy.all import *
from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.inet6 import IPv6

pkt = IP(dst="127.0.0.1")/UDP(dport=8080,sport=47777)/('B'.encode())

send(pkt)