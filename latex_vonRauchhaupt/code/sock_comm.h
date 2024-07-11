
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
#include <signal.h>

#include <io_ipc.h>

#define MAX_AMOUNT_OF_SOCKETS 32

// This has to be long enough to fit the number or the socket and a terminating null byte
#define SOCKET_TEMPLATE_LENGTH 128
#define SOCKET_NAME_TEMPLATE "/tmp/unixDomainSock4SF2B_"

/**
 * @brief Enum to specify if thread calling a function is either writer or reader
 *
 *
 */
enum sock_role_t{
    SOCK_WRITER,
    SOCK_READER
};


// Socket writer parameters
/**
 * @brief Struct that contains all information for a writer thread
 *
 *
 */
struct sock_writer_arg_t
{
    // Temporarily fixed length of socket path
    // Issue: Variable length arrays are not possible in a static context
    char socketPathNames[MAX_AMOUNT_OF_SOCKETS][SOCKET_TEMPLATE_LENGTH];
    struct sockaddr_un socketConnections[SOCKET_TEMPLATE_LENGTH];
    int socketRecvs[MAX_AMOUNT_OF_SOCKETS];
    int writeSockets[MAX_AMOUNT_OF_SOCKETS];
};


// Socket reader parameters
/**
 * @brief Struct that contains all information for a reader thread
 *
 *
 */
struct sock_reader_arg_t
{
	// Temporarily fixed length of socket path
    // Issue: Variable length arrays are not possible in a static context
    char socketPathName[SOCKET_TEMPLATE_LENGTH];
    struct sockaddr_un address;
	int sizeOfAddressStruct;
    int readSocket;
	int clientSockets[MAX_AMOUNT_OF_SOCKETS];
};


/**
 * @brief Union that provides either writer or reader arguments for a called function
 *
 *
 */
union sock_arg_t{
    struct sock_writer_arg_t wargs;
    struct sock_reader_arg_t rargs;
};


/**
 * @brief Initialize all required structs for socket communication
 *
 * @param args struct to writer/reader information
 * @param role specify if a reader or writer process is calling this function
 * @return 0 on success, otherwise a specific error code
 */
int sock_init(union sock_arg_t *sock_args,
              int role);


/**
 * @brief Sends multiple messages of a given buffer to all available sockets
 *
 * @param args struct to writer information
 * @param iovecs vector structure with base pointer to start of data and length of data
 * @param invalid_count number of lines to be written to the sockets
 * @param maxNumOfSocks maximum amount of receiving sockets
 * @return int number of sent messages to the sockets
 */
int sock_writev(struct sock_writer_arg_t *sock_args,
                struct iovec *log_iovs,
                uint16_t invalid_count,
                uint16_t maxNumOfSocks);


/**
 * @brief Reads all available messages into a given buffer
 *
 * @param args struct to reader information
 * @param iovecs vector structure with base pointer to start of data and length of data
 * @return int number of read messages
 */
int sock_readv(struct sock_reader_arg_t *sock_args,
               struct iovec *iovecs);


/**
 * @brief Start cleanup for writer/reader thread
 *
 * @param args struct to writer/reader information
 * @param role specify if a reader or writer process is calling this function
 * @return 0 on success, otherwise a specific error code
 */
int sock_finalize(union sock_arg_t *sock_args, int role);


/**
 * @brief Cleanup for writer/reader thread
 *
 * @param args struct to writer/reader information
 * @param role specify if a reader or writer process is calling this function
 * @return 0 on success, otherwise a specific error code
 */
int sock_cleanup(union sock_arg_t *sock_args, int role);


#endif