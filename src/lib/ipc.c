#include "include/io_ipc.h"


static int shm_attach_header(void * shm, struct shm_header_t ** hdr_ptr, uint32_t size, bool init){

    if(shm == NULL || hdr_ptr == NULL){
        return IPC_ERROR;
    }

    if(size < sizeof(struct shm_header_t)){
        return IPC_ERROR;
    }

    *hdr_ptr = shm;

    if(init){
        pthread_mutexattr_t attr;
        if(pthread_mutexattr_init(&attr)){
            return IPC_ERROR;
        }
        if(pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)){
            return IPC_ERROR;
        }
        if(pthread_mutex_init(&(*hdr_ptr)->read_lock, &attr)){
            pthread_mutexattr_destroy(&attr);
            return IPC_ERROR;
        }
        if(pthread_mutex_init(&(*hdr_ptr)->write_lock, &attr)){
            pthread_mutexattr_destroy(&attr);
            return IPC_ERROR;
        }

        pthread_mutexattr_destroy(&attr);

        (*hdr_ptr)->size = size - sizeof(struct shm_header_t);
        (*hdr_ptr)->read_upper = 0;
        (*hdr_ptr)->read_lower = 0;
        (*hdr_ptr)->write_upper = 0;
        (*hdr_ptr)->write_lower = 0;
        
        (*hdr_ptr)->shm_start = (void *)((char *) shm + sizeof(struct shm_header_t));
    }
    
    return IPC_SUCCESS;
}

int shm_put(struct shm_header_t * shm_hdr, void * src, uint32_t wsize){

    int retval = IPC_SUCCESS;

    if(shm_hdr == NULL || src == NULL){
        return IPC_ERROR;
    }

    if(wsize == 0){
        return IPC_SUCCESS;
    }

    if(pthread_mutex_lock(&shm_hdr->write_lock)){
        pthread_mutex_unlock(&shm_hdr->write_lock);
        return IPC_ERROR;
    }

    atomic_uint_fast32_t old_write_index = atomic_load(&shm_hdr->write_upper); 
    atomic_uint_fast32_t new_write_index = (old_write_index + wsize) % shm_hdr->size;
    uint32_t read_index = atomic_load(&shm_hdr->read_lower); 
    uint32_t writable = (old_write_index > read_index) ? (shm_hdr->size - old_write_index) + read_index : read_index - old_write_index;

    if(read_index == old_write_index){
        writable = shm_hdr->size;
    }

    if(wsize > writable){
        pthread_mutex_unlock(&shm_hdr->write_lock);
        return IPC_ERROR;
    }

    atomic_store(&shm_hdr->write_upper,new_write_index);

    pthread_mutex_unlock(&shm_hdr->write_lock);

    if(new_write_index < old_write_index){
        if(memcpy((void *)((char *)shm_hdr->shm_start + old_write_index),src,(wsize-new_write_index)) == NULL){
            retval = IPC_ERROR;
        }
        if(memcpy((void *)((char *)shm_hdr->shm_start),(void *)((char *)src + wsize-new_write_index),(new_write_index)) == NULL){
            retval = IPC_ERROR;
        }
    } else {
        if(memcpy((void *)((char *)shm_hdr->shm_start + old_write_index),src,wsize) == NULL){
            retval = IPC_ERROR;
        }
    }

    if(pthread_mutex_lock(&shm_hdr->write_lock)){
        pthread_mutex_unlock(&shm_hdr->write_lock);
        return IPC_ERROR;
    }

    atomic_compare_exchange_strong(&shm_hdr->write_lower,&old_write_index,new_write_index);

    pthread_mutex_unlock(&shm_hdr->write_lock);

    return retval;
}

int64_t shm_get(struct shm_header_t * shm_hdr, void * dst, uint32_t rsize){

    int64_t bytes_read = rsize;

    if(shm_hdr == NULL || dst == NULL){
        return IPC_ERROR;
    }

    if(rsize == 0){
        return IPC_SUCCESS;
    }

    if(pthread_mutex_lock(&shm_hdr->read_lock)){
        pthread_mutex_unlock(&shm_hdr->read_lock);
        return IPC_ERROR;
    }

    atomic_uint_fast32_t old_read_index = atomic_load(&shm_hdr->read_upper); 
    uint32_t write_index = atomic_load(&shm_hdr->write_lower); 
    uint32_t readable = (old_read_index > write_index) ? (shm_hdr->size - old_read_index) + write_index : write_index - old_read_index;
    atomic_uint_fast32_t new_read_index = (rsize > readable) ? (old_read_index + readable) % shm_hdr->size : (old_read_index + rsize) % shm_hdr->size;

    atomic_store(&shm_hdr->read_upper,new_read_index);

    pthread_mutex_unlock(&shm_hdr->write_lock);

    if(new_read_index < old_read_index){
        if(memcpy((void *)((char *)shm_hdr->shm_start + old_read_index),dst,(rsize-new_read_index)) == NULL){
            bytes_read = IPC_ERROR;
        }
        if(memcpy((void *)((char *)shm_hdr->shm_start),(void *)((char *)dst + rsize-new_read_index),(new_read_index)) == NULL){
            bytes_read = IPC_ERROR;
        }
    } else {
        if(memcpy((void *)((char *)shm_hdr->shm_start + old_read_index),dst,rsize) == NULL){
            bytes_read = IPC_ERROR;
        }
    }

    if(pthread_mutex_lock(&shm_hdr->write_lock)){
        pthread_mutex_unlock(&shm_hdr->write_lock);
        return IPC_ERROR;
    }

    atomic_compare_exchange_strong(&shm_hdr->read_lower,&old_read_index,new_read_index);

    pthread_mutex_unlock(&shm_hdr->write_lock);

    return bytes_read;
}

int shm_attach(int shmid, struct shm_header_t **hdr_ptr, uint32_t size, bool init){

    if(hdr_ptr == NULL){
        return IPC_ERROR;
    }

    void * shm_ptr;

    if(*((int *)(shm_ptr = shmat(shmid,NULL,0))) == -1)
	{
		return IPC_ERROR;
	}

    if(shm_attach_header(shm_ptr,hdr_ptr,size,init)){
        return IPC_ERROR;
    }

    return IPC_SUCCESS;
}

int shm_detach(struct shm_header_t * hdr){

    if(hdr == NULL){
        return IPC_ERROR;
    }

    if(shmdt(hdr) < 0){
		return IPC_ERROR;
	}

    return IPC_SUCCESS;

}