#ifndef _IO_IPC_H
#define _IO_IPC_H
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>


#include "io_ipc/shm_ringbuf.h"
#include "io_ipc/msgq.h"
#include "io_ipc/sock.h"

#define IO_IPC_SUCCESS (0)
#define IO_IPC_ARG_ERR (-1)
#define IO_IPC_MEM_ERR (-2)
#define IO_IPC_NULLPTR_ERR (-3)
#define IO_IPC_MUTEX_ERR (-3)
#define IO_IPC_SIZE_ERR (-4)

#define PAGESIZE 4096

enum ipc_type_t 
{
    SHM,
    SOCKET,
    QUEUE,
    DISK,
};

union ipc_arg_t
{
    void * placeholder;
};

int ipc_init(union ipc_arg_t * arg, enum ipc_type_t type);

int ipc_put(union ipc_arg_t * arg, enum ipc_type_t type, void * data, uint8_t size);

int ipc_get(union ipc_arg_t * arg, enum ipc_type_t type, void * buffer, uint8_t bufsize);

int ipc_finalize(union ipc_arg_t * arg, enum ipc_type_t type);

#endif