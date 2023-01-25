#ifndef IPC_H
#define IPC_H
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

#define IPC_ERROR (-1)
#define IPC_SUCCESS (0)

enum ipc_type_t 
{
    SHM,
    SOCKET,
    PIPE,
    QUEUE,
    DISK,
};

struct shm_header_t {
    uint32_t size;
    atomic_uint_fast32_t read_upper;
    atomic_uint_fast32_t read_lower;
    atomic_uint_fast32_t write_upper;
    atomic_uint_fast32_t write_lower;
    pthread_mutex_t write_lock;
    pthread_mutex_t read_lock;
    void * shm_start;
};

int shm_attach(int shmid, struct shm_header_t **hdr_ptr, uint32_t size, bool init);

int shm_detach(struct shm_header_t * hdr);


int64_t shm_get(struct shm_header_t * shm_hdr, void * rbuf, uint32_t bufsize);

struct shm_parameters_t 
{
    void * shm_start;
    uint32_t size;
    atomic_uint_fast32_t * read_index;
    atomic_uint_fast32_t * write_index;
    pthread_mutex_t lower_index_lock;
    pthread_mutex_t upper_index_lock;
    atomic_uint_fast32_t * upper_index;
    atomic_uint_fast32_t * lower_index;
    
};

#endif