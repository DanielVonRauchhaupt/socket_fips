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

// Local includes
#include "shm_ringbuf.h"
#include "msgq.h"
#include "sock.h"

// Error types
#define IO_IPC_SUCCESS (0)
#define IO_IPC_ARG_ERR (-1)
#define IO_IPC_MEM_ERR (-2)
#define IO_IPC_NULLPTR_ERR (-3)
#define IO_IPC_MUTEX_ERR (-3)
#define IO_IPC_SIZE_ERR (-4)

#define PAGESIZE 4096

// IPC types
enum ipc_type_t 
{
    SHM,
    SHM_S,
    SOCKET,
    QUEUE,
    DISK,
};

#endif