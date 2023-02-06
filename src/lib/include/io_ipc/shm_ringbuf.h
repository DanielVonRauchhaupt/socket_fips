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
    uint32_t size;
    uint8_t segment_count;
    struct shm_rbuf_seg_hdr_t ** segment_heads;
    bool create;
    struct shm_rbuf_global_hdr_t * head;
};

struct shm_rbuf_global_hdr_t {
    uint8_t segment_count;
    uint32_t size;
};

struct shm_rbuf_seg_hdr_t {
    uint32_t size;
    atomic_uint_fast32_t read_index;
    atomic_uint_fast32_t write_index;
};

int shm_rbuf_init(struct shm_rbuf_arg_t * args);

int shm_rbuf_finalize(struct shm_rbuf_arg_t * args);

int shm_rbuf_write(struct shm_rbuf_arg_t * args, void * src, uint8_t wsize, uint32_t segment_id);

int shm_rbuf_read(struct shm_rbuf_arg_t * args, void * rbuf, uint8_t bufsize, uint32_t segment_id);

#endif