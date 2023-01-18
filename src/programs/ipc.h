#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>

enum ipc_type_t 
{
    SHM,
    SOCKET,
    PIPE,
    QUEUE,
    DISK,
};

union ipc_parameters_t 
{

};

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

struct sock_parameters_t 
{

};


int8_t ipc_init(union ipc_parameters_t * comm, enum ipc_type_t type, const char * arg);