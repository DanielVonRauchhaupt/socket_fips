#ifndef _RBUF_H_
#define _RBUF_H_
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define RBUF_NULLPTR_ERR (-1)
#define RBUF_ARG_ERR (-2)
#define RBUF_MEM_ERR (-3)
#define RBUF_MUTEX_ERR (-4)
#define RBUF_SIZE_ERR (-5)
#define RBUF_WRITE_ERR (-6)
#define RBUF_SUCCESS 0

struct ringbuf_t {

    pthread_mutex_t lock;
    uint32_t free;
    void * read_ptr;
    void * write_ptr;
    void * base_ptr;
    void * top_ptr;
};

int8_t ringbuf_init(struct ringbuf_t * rbuf, uint32_t nybtes);

int8_t ringbuf_write(struct ringbuf_t * rbuf, void * src, uint32_t nbytes);

int8_t ringbuf_read(struct ringbuf_t * rbuf, void * dst, uint32_t nbytes);

int8_t ringbuf_write_to_file(struct ringbuf_t * rbuf, FILE * file);

int8_t ringbuf_destroy(struct ringbuf_t * rbuf);


#endif
