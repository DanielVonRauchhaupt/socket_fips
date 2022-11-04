CC = clang
CFLAGS = -Wall -Wextra -pedantic -o3

all: client server pipe socket shmem

server: udp_server.c
	$(CC) $(CFLAGS) $^ -o $@

client: test_client.c
	$(CC) $(CFLAGS) $^ -o $@

pipe: pipe_test.c
	$(CC) $(CFLAGS) $^ -o $@

socket: socket_test.c
	$(CC) $(CFLAGS) $^ -o $@

shmem: shmem_test.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -rf *.o client server pip socket shmem
