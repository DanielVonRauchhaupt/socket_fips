CC = gcc
CFLAGS = -Wall -Wextra -pedantic -o3

all: client server

server: udp_server.c
	$(CC) $(CFLAGS) $^ -o $@

client: test_client.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -rf *.o client server
