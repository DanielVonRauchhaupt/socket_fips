#ifndef _SHM_RBUF_H
#define _SHM_RBUF_H

#include <stdint.h>

struct shm_rbuf_hdr_t {
    uint8_t rbuf_count;
    uint32_t size;
};

int shm_attach(int shmid, struct shm_header_t **hdr_ptr, uint32_t size, bool init);

int shm_detach(struct shm_header_t * hdr);

int shm_put(struct shm_header_t * shm_hdr, void * src, uint32_t wsize);

int shm_get(struct shm_header_t * shm_hdr, void * rbuf, uint32_t bufsize);


#endif