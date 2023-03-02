#include "include/shm_ringbuf.h"

static void shm_cleanup(struct shm_rbuf_arg_t * args){

    free(args->segment_locks);
    free(args->segment_heads);
    free(args->segment_rindices);

    shmdt(args->head);

    if(args->create){
        shmctl(args->shmid, IPC_RMID, NULL);
    }

}


int shm_rbuf_init(struct shm_rbuf_arg_t * args){

    if(args == NULL)
    {
        return IO_IPC_NULLPTR_ERR;
    }

    if(args->create && (args->line_size == 0 || args->lines < args->segment_count)){
        return IO_IPC_ARG_ERR;
    }

    key_t key = ftok(args->key_path,0);

    if(key == -1){
        return errno;
    }

    int shm_flag = 0;

    if(args->create){

        shm_flag |= IPC_CREAT | IPC_EXCL;

    }

    if(args->lines * args->line_size > PAGESIZE){

        shm_flag |= SHM_HUGETLB;
    }

    size_t size = sizeof(struct shm_rbuf_global_hdr_t) + args->segment_count * (sizeof(struct shm_rbuf_seg_hdr_t) + args->lines * args->line_size);

    if((args->shmid = shmget(key,size,shm_flag)) < 0){
        return errno;
    }

    if(*((int *)(args->head = (struct shm_rbuf_global_hdr_t *) shmat(args->shmid,NULL,0))) == -1){
        int reval = errno;
        shm_cleanup(args);
        return errno;
    }

    if(args->create){
        args->head->lines = args->lines;
        args->head->line_size = args->line_size;
        args->head->segment_count = args->segment_count;
        args->head->overwrite = args->overwrite;
    } 
    
    else {
        args->lines = args->head->lines;
        args->line_size = args->head->line_size;
        args->segment_count = args->head->segment_count;
        args->overwrite = args->head->overwrite;
    } 

    if(args->segment_count == 0 || args->lines == 0 || args->line_size == 0){
        shm_cleanup(args);
        return IO_IPC_ARG_ERR;
    }

    if((args->segment_heads = (struct shm_rbuf_seg_hdr_t **) calloc(sizeof(struct shm_rbuf_seg_hdr_t *),args->segment_count)) == NULL){
        shm_cleanup(args);
        return IO_IPC_MEM_ERR;
    }

    if((args->segment_locks = (pthread_mutex_t *) calloc(sizeof(pthread_mutex_t),args->segment_count)) == NULL){
        shm_cleanup(args);
        return IO_IPC_MEM_ERR;
    }

    if((args->segment_rindices = (uint32_t *) calloc(sizeof(uint32_t),args->segment_count)) == NULL){
        shm_cleanup(args);
        return IO_IPC_MEM_ERR;
    }

    uint32_t offset = sizeof(struct shm_rbuf_global_hdr_t);
    uint32_t segment_size = sizeof(struct shm_rbuf_seg_hdr_t) + args->line_size * args->lines;

    for(int i = 0; i < args->segment_count; i++){

        struct shm_rbuf_seg_hdr_t * seg_hdr = (struct shm_rbuf_seg_hdr_t *)((char *)args->head + offset);

        if(args->create){

            seg_hdr->lines = args->lines;
            seg_hdr->write_index = 0;
            seg_hdr->read_index = 0;
            seg_hdr->read_count = 0;

        }

        args->segment_heads[i] = seg_hdr;
        offset += segment_size;

    }

    return IO_IPC_SUCCESS;

}


int shm_rbuf_finalize(struct shm_rbuf_arg_t * args){

    if(args == NULL){
        return IO_IPC_NULLPTR_ERR;
    }

    int retval = IO_IPC_SUCCESS;
    
    if(shmdt(args->head) < 0){
        int retval = errno;
        shm_cleanup(args);
    }

    else if(args->create){
        if(shmctl(args->shmid, IPC_RMID, NULL) < 0){
            retval == errno;
        }
    }

    free(args->segment_heads);
    free(args->segment_locks);
    free(args->segment_rindices);

    return retval;

}

int shm_rbuf_write(struct shm_rbuf_arg_t * args, void * src, uint16_t wsize, uint32_t segment_id){

    struct shm_rbuf_seg_hdr_t * segment;

    if(args == NULL || src == NULL || (segment = args->segment_heads[segment_id]) == NULL){
        return IO_IPC_NULLPTR_ERR;
    }

    else if(segment_id >= args->segment_count || wsize > args->line_size){
        return IO_IPC_ARG_ERR;
    }

    if(pthread_mutex_lock(&args->segment_locks[segment_id]) < 0){
        pthread_mutex_unlock(&args->segment_locks[segment_id]);
        return IO_IPC_MUTEX_ERR;
    }

    if(args->overwrite){

        uint32_t write_index = atomic_load(&segment->write_index);

        if(write_index == )

    }

    

    return IO_IPC_SUCCESS;
}

int shm_rbuf_read(struct shm_rbuf_arg_t * args, void * rbuf, uint16_t bufsize, uint32_t segment_id){
    
    struct shm_rbuf_seg_hdr_t * segment;

    if(args == NULL || rbuf == NULL || (segment = args->segment_heads[segment_id]) == NULL){
        return IO_IPC_NULLPTR_ERR;
    }

    if(segment_id >= args->segment_count){
        return IO_IPC_ARG_ERR;
    }

    if(bufsize == 0){
        return 0;
    }

    uint32_t write_index = atomic_load(&segment->write_index);

    if(write_index == segment->read_index){
        return 0;
    }
    
    char * base_ptr = ((char *)segment + sizeof(struct shm_rbuf_seg_hdr_t) + segment->read_index);
    uint8_t rsize = *(base_ptr++);

    if(rsize > bufsize){
        return IO_IPC_SIZE_ERR;
    }

    uint8_t overlap = ((segment->read_index + rsize + 1) > segment->size) ? (segment->read_index + rsize + 1) % segment->size : 0;

    if(overlap){
        if(memcpy(rbuf,(void *)base_ptr,rsize-overlap) == NULL){
            return IO_IPC_MEM_ERR;
        }
        if(memcpy((void *)((char * )rbuf + (rsize-overlap)),(void *)((char *) segment + sizeof(struct shm_rbuf_seg_hdr_t)),overlap) == NULL){
            return IO_IPC_MEM_ERR;
        }

        atomic_store(&segment->read_index,overlap);
    }

    else{
        if(memcpy(rbuf,(void *)base_ptr,rsize) == NULL){
            return IO_IPC_MEM_ERR;
        }

        atomic_fetch_add(&segment->read_index,rsize+1);
    }

    return rsize;

}