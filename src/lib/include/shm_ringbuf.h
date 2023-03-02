#ifndef _SHM_RINGBUF_H
#define _SHM_RINGBUF_H

#include <stdint.h>
#include <sys/shm.h>
#include <pthread.h>
#include <stdbool.h>
#include <io_ipc.h>
#include <stdatomic.h>

struct shm_rbuf_arg_t {
    const char * key_path;
    int shmid;
    uint16_t line_size;
    uint32_t lines;
    uint8_t segment_count;
    uint8_t reader_count;
    struct shm_rbuf_seg_hdr_t ** segment_heads;
    pthread_mutex_t * segment_locks;
    uint32_t * segment_rindices;
    bool create;
    bool overwrite;
    struct shm_rbuf_global_hdr_t * head;
};

struct shm_rbuf_global_hdr_t {
    uint8_t segment_count;
    bool overwrite;
    uint16_t line_size;
    uint32_t lines;
    uint8_t reader_count;
    
};

struct shm_rbuf_seg_hdr_t {
    uint32_t lines;
    atomic_uint_fast32_t write_index;
    atomic_uint_fast32_t read_index;
    atomic_uint_fast8_t read_count;
    
};

int shm_rbuf_init(struct shm_rbuf_arg_t * args);

int shm_rbuf_finalize(struct shm_rbuf_arg_t * args);

int shm_rbuf_write(struct shm_rbuf_arg_t * args, void * src, uint16_t wsize, uint32_t segment_id);

int shm_rbuf_read(struct shm_rbuf_arg_t * args, void * rbuf, uint16_t bufsize, uint32_t segment_id);

#endif