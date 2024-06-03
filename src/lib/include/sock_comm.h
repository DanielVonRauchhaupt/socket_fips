
#ifndef _SOCKET_H
#define _SOCKET_H

#pragma once
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <math.h>
#include <sys/select.h>

#include <io_ipc.h>

#define MAX_AMOUNT_OF_SOCKETS 32
// This has to be long enough to fit the number or the socket and a terminating \0
#define SOCKET_TEMPLATE_LENGTH 128
#define SOCKET_NAME_TEMPLATE "/tmp/unixDomainSock4SF2B_"

enum sock_role_t{
    SOCK_WRITER,
    SOCK_READER
};

// Socket writer parameters
struct sock_writer_arg_t
{
    // Temporarily fixed length of socket path
    // Issue: Varaible length arrays are not possible in a static context
    char socketPathNames[MAX_AMOUNT_OF_SOCKETS][SOCKET_TEMPLATE_LENGTH];
    struct sockaddr_un socketConnections[SOCKET_TEMPLATE_LENGTH];
    int socketRecvs[MAX_AMOUNT_OF_SOCKETS];
    int writeSockets[MAX_AMOUNT_OF_SOCKETS];
};

// Socket reader parameters
struct sock_reader_arg_t
{
	// Temporarily fixed length of socket path
    // Issue: Varaible length arrays are not possible in a static context
    char socketPathName[SOCKET_TEMPLATE_LENGTH];
    struct sockaddr_un address;
	int sizeOfAddressStruct;
    int readSocket;
	int clientSockets[MAX_AMOUNT_OF_SOCKETS];
};

union sock_arg_t{
    struct sock_writer_arg_t wargs;
    struct sock_reader_arg_t rargs;
};

int sock_init(union sock_arg_t *sock_arg, int role);

int sock_writev(struct sock_writer_arg_t *sock_arg, struct iovec *log_iovs, uint16_t invalid_count, uint16_t numOfSocks);

int sock_readv(struct sock_reader_arg_t *sock_arg, struct iovec *iovecs);

// Currently only supports the writer side of the communication
// The reader side finalize is only 1 line long
int sock_finalize(union sock_arg_t *sock_arg, int role);

int sock_cleanup(union sock_arg_t *sock_args, int role);


#endif