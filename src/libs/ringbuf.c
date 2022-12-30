#include "ringbuf.h"

int8_t ringbuf_init(struct ringbuf_t * rbuf, uint32_t nbytes)
{
    if(rbuf == NULL){
        return RBUF_ARG_ERR;
    }

    if((rbuf->base_ptr = malloc(nbytes)) == NULL){
        return RBUF_MEM_ERR;
    }

    rbuf->read_ptr = rbuf->base_ptr;
    rbuf->write_ptr = rbuf->base_ptr;
    rbuf->top_ptr = (void*)((char*)rbuf->base_ptr + nbytes);
    rbuf->free = nbytes;

    if(pthread_mutex_init(&rbuf->lock,NULL)){
        return RBUF_MUTEX_ERR;
    }
    
    return RBUF_SUCCESS;    
}

int8_t ringbuf_write(struct ringbuf_t * rbuf, void * src, uint32_t nbytes){
    if(rbuf == NULL || src == NULL){
        return RBUF_ARG_ERR;
    }

    if(pthread_mutex_lock(&rbuf->lock)){
        return RBUF_MUTEX_ERR;
    }

    if(nbytes > rbuf->free){
        pthread_mutex_unlock(&rbuf->lock);
        return RBUF_SIZE_ERR;
    }

    uint32_t delta = (char*)rbuf->top_ptr - (char*)rbuf->write_ptr;

    if(delta < nbytes){
        if(memcpy(rbuf->write_ptr,src,delta) == NULL || memcpy(rbuf->base_ptr,(void*)((char*)src+delta),nbytes-delta) == NULL){
            pthread_mutex_unlock(&rbuf->lock);
            return RBUF_MEM_ERR;
        }
        rbuf->write_ptr = (void*)((char*)rbuf->base_ptr + (nbytes-delta));
    }

    else{
        if(memcpy(rbuf->write_ptr,src,nbytes) == NULL){
            pthread_mutex_unlock(&rbuf->lock);
            return RBUF_MEM_ERR;
        }
        rbuf->write_ptr = (void*)((char*)rbuf->write_ptr + nbytes);
    }

    rbuf->free -= nbytes;

    if(pthread_mutex_unlock(&rbuf->lock)){
        return RBUF_MUTEX_ERR;
    }

    return rbuf->free;

}

int8_t ringbuf_write_to_file(struct ringbuf_t * rbuf, FILE * file){
    if(rbuf == NULL){
        return RBUF_ARG_ERR;
    }

    if(pthread_mutex_lock(&rbuf->lock)){
        return RBUF_MUTEX_ERR;
    }

    uint32_t size = (char*)rbuf->top_ptr - (char*)rbuf->base_ptr;

    if(((char*)rbuf->write_ptr - (char*)rbuf->read_ptr) < 0){
        uint32_t delta = (char*)rbuf->top_ptr - (char*)rbuf->read_ptr;
        if(fwrite(rbuf->read_ptr,delta,1,file)||fwrite(rbuf->base_ptr,(char*)rbuf->write_ptr-(char*)rbuf->base_ptr,1,file)){
            pthread_mutex_unlock(&rbuf->lock);
            return RBUF_WRITE_ERR;
        }       
    }

    else {
        if(fwrite(rbuf->read_ptr,(char*)rbuf->write_ptr - (char*)rbuf->read_ptr,1,file) == 0){
            pthread_mutex_unlock(&rbuf->lock);
            return RBUF_WRITE_ERR;
        }
    }

    rbuf->write_ptr = rbuf->read_ptr;
    rbuf->free = size;

    if(pthread_mutex_unlock(&rbuf->lock)){
        return RBUF_MUTEX_ERR;
    }

    return RBUF_SUCCESS;

}

int8_t ringbuf_destroy(struct ringbuf_t * rbuf){
    if(rbuf == NULL){
        return RBUF_ARG_ERR;
    }

    if(pthread_mutex_lock(&rbuf->lock)){
        return RBUF_MUTEX_ERR;
    }

    free(rbuf->base_ptr);

    if(pthread_mutex_destroy(&rbuf->lock)){
        return RBUF_MUTEX_ERR;
    }

    rbuf->base_ptr = NULL;
    rbuf->top_ptr = NULL;
    rbuf->read_ptr = NULL;
    rbuf->write_ptr = NULL;
    rbuf->free = 0;

    return RBUF_SUCCESS;
}