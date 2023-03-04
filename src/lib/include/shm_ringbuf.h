#ifndef _SHMRBUF_H
#define _SHMRBUF_H

#include <stdint.h>
#include <sys/shm.h>
#include <pthread.h>
#include <stdbool.h>
#include <io_ipc.h>
#include <stdatomic.h>

struct shmrbuf_writer_arg_t {
    const char * shm_key;
    uint16_t line_size;
    uint32_t lines;
    uint8_t segment_count;
    uint8_t reader_count;
    bool overwrite;
    struct shmrbuf_global_hdr_t * head;
    struct shmrbuf_seg_whdr_t * segment_hdrs;
    int shmid;
};

struct shmrbuf_reader_arg_t {
    const char * shm_key;
    int shmid;
    uint8_t reader_index;
    struct shmrbuf_global_hdr_t * head;
    struct shmrbuf_seg_rhdr_t * segment_hdrs;
};


struct shmrbuf_global_hdr_t {
    uint8_t segment_count;
    bool overwrite;
    uint16_t line_size;
    uint32_t lines;
    uint8_t reader_count;
    atomic_uint_fast8_t reader_index;
    
};

struct shmrbuf_seg_rhdr_t {

    atomic_uint_fast32_t * write_index;
    atomic_uint_fast32_t * read_index;
    pthread_mutex_t segment_lock;
    void * data;
    
};

struct shmrbuf_seg_whdr_t {

    atomic_uint_fast32_t * write_index;
    atomic_uint_fast32_t * first_reader;
    void * data;
    
};

enum shmrbuf_role_t {
    SHMRBUF_WRITER,
    SHMRBUF_READER
};

union shmrbuf_arg_t {

    struct shmrbuf_writer_arg_t wargs;
    struct shmrbuf_reader_arg_t rargs;

};

int shmrbuf_init(union shmrbuf_arg_t * args, enum shmrbuf_role_t role);

int shmrbuf_finalize(union shmrbuf_arg_t *, enum shmrbuf_role_t role);

int shmrbuf_write(struct shmrbuf_writer_arg_t * args, void * src, uint16_t wsize, uint8_t segment_id);

int shmrbuf_read(struct shmrbuf_reader_arg_t * args, void * rbuf, uint16_t bufsize, uint8_t segment_id);

#endif