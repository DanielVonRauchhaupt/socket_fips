import socket
from random import randrange

IP = "0.0.0.0"
PORT = 8080

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

for i in range(100):

    sock.sendto(randrange(0,255).to_bytes(1,'big'),(IP,PORT))


