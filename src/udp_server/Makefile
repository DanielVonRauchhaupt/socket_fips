CC := gcc
CCFLAGS := -o3 -pthread
DBGFLAGS := -Wall -Wextra -pedantic -g


TARGET := udp_server
TARGET_DEBUG := udp_server_debug
SRC := udp_server.c ip_to_str.c ringbuf.c

# default rule
default: debug

# non-phony targets
$(TARGET): $(SRC)
	$(CC) $(CCFLAGS) -o $@ $(SRC)

$(TARGET_DEBUG): $(SRC)
	$(CC) $(CCFLAGS) $(DBGFLAGS) -o $@ $(SRC)


.PHONY: all
all: $(TARGET)

.PHONY: debug
debug: $(TARGET_DEBUG)

.PHONY: clean
clean:
	rm -f udp_server udp_server_debug
