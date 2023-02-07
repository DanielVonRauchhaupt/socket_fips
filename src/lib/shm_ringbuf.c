#include "include/io_ipc/shm_ringbuf.h"

static void shm_cleanup(struct shm_rbuf_arg_t * args){

    shmdt(args->head);

    if(args->create){
        shmctl(args->shmid, IPC_RMID, NULL);
    }

}

static uint32_t init_seg_hdr(struct shm_rbuf_seg_hdr_t * hdr,uint32_t base_size, uint8_t * padding){
    hdr->read_index = 0;
    hdr->write_index = 0;
    hdr->size = (*(padding)--) ? base_size + 1 : base_size;
    return hdr->size + sizeof(struct shm_rbuf_seg_hdr_t);
}


int shm_rbuf_init(struct shm_rbuf_arg_t * args){

    if(args == NULL){
        return IO_IPC_NULLPTR_ERR;
    }

    if(args->size < (sizeof(struct shm_rbuf_global_hdr_t) +  args->segment_count * sizeof(struct shm_rbuf_seg_hdr_t))){
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

    if(args->size > PAGESIZE){

        shm_flag |= SHM_HUGETLB;
    }

    if((args->shmid = shmget(key,args->size,shm_flag)) < 0){
        return errno;
    }

    if(*((int *)(args->head = (struct shm_rbuf_global_hdr_t *) shmat(args->shmid,NULL,0)))==-1){
        int reval = errno;
        shm_cleanup(args);
        return errno;
    }

    if(args->create){
        args->head->size = args->size - sizeof(struct shm_rbuf_global_hdr_t);
        args->head->segment_count = args->segment_count;
    } 
    
    else {
        args->size = args->head->size;
        args->segment_count = args->head->segment_count;
    } 

    if(args->segment_count == 0){
        shm_cleanup(args);
        return IO_IPC_ARG_ERR;
    }

    if((args->segment_heads = (struct shm_rbuf_seg_hdr_t **) calloc(sizeof(struct shm_rbuf_seg_hdr_t *),args->segment_count)) == NULL){
        shm_cleanup(args);
        return IO_IPC_MEM_ERR;
    }

    uint8_t padding = args->head->size % args->segment_count;
    uint32_t base_size = (args->head->size / args->segment_count) - sizeof(struct shm_rbuf_seg_hdr_t);
    uint32_t prior_size;

    args->segment_heads[0] = (struct shm_rbuf_seg_hdr_t *) ((char *)(args->head)+sizeof(struct shm_rbuf_global_hdr_t));

    if(args->create){
        prior_size = init_seg_hdr(args->segment_heads[0],base_size,&padding);
    }

    else {
        prior_size = args->segment_heads[0]->size + sizeof(struct shm_rbuf_seg_hdr_t);
    }

    for(int i = 1; i < args->segment_count; i++){

        args->segment_heads[i] = (struct shm_rbuf_seg_hdr_t *) ((char *)(args->segment_heads[i-1]) + prior_size);

        if(args->create){
            prior_size = init_seg_hdr(args->segment_heads[i],base_size,&padding);
        }

        else {
            prior_size = args->segment_heads[i]->size + sizeof(struct shm_rbuf_seg_hdr_t);
        }

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

    return retval;

}

int shm_rbuf_write(struct shm_rbuf_arg_t * args, void * src, uint8_t wsize, uint32_t segment_id){

    struct shm_rbuf_seg_hdr_t * segment;

    if(args == NULL || src == NULL || (segment = args->segment_heads[segment_id]) == NULL){
        return IO_IPC_NULLPTR_ERR;
    }

    else if(segment_id >= args->segment_count){
        return IO_IPC_ARG_ERR;
    }

    uint32_t free_bytes, read_index = atomic_load(&segment->read_index);

    if(read_index == segment->write_index){
        free_bytes = segment->size;
    } 

    else if(read_index < segment->write_index){
        free_bytes = segment->write_index - read_index;
    }

    else {
        free_bytes = (segment->size - read_index) + segment->write_index;
    }

    if(free_bytes < wsize + 2){
        return IO_IPC_SIZE_ERR;
    }

    char * base_ptr = (((char *) segment) + sizeof(struct shm_rbuf_seg_hdr_t) + segment->write_index);
    *(base_ptr++) = wsize;
    

    uint8_t overlap = ((read_index + wsize + 1) > segment->size) ? (read_index + wsize + 1) % segment->size : 0;

    if(overlap){

        if(memcpy((void *)base_ptr,src,wsize-overlap) == NULL){
            return IO_IPC_MEM_ERR;
        }

        if(memcpy((void *)((char *)segment+sizeof(struct shm_rbuf_seg_hdr_t)),(void *)((char *)src + (wsize-overlap)),overlap) == NULL){
            return IO_IPC_MEM_ERR;
        }

        atomic_store(&segment->write_index,overlap);

    }

    else {
        if(memcpy(base_ptr,src,wsize) == NULL){
            return IO_IPC_MEM_ERR;
        }

        atomic_fetch_add(&segment->write_index,wsize+1);
    }

    return IO_IPC_SUCCESS;
}

int shm_rbuf_read(struct shm_rbuf_arg_t * args, void * rbuf, uint8_t bufsize, uint32_t segment_id){
    
    struct shm_rbuf_seg_hdr_t * segment;

    if(args == NULL || segment_id < args->segment_count  || rbuf == NULL || (segment = args->segment_heads[segment_id]) == NULL){
        return IO_IPC_NULLPTR_ERR;
    }

    if(bufsize == 0){
        return 0;
    }

    uint32_t write_index = atomic_load(&segment->write_index);

    if(write_index == segment->read_index){
        return 0;
    }
    
    char * base_ptr = ((char *)segment + sizeof(struct shm_rbuf_seg_hdr_t) + segment->read_index);
    uint8_t rsize = *base_ptr;

    if(rsize > bufsize){
        return IO_IPC_SIZE_ERR;
    }

    uint8_t overlap = ((segment->write_index + rsize + 1) > segment->size) ? (segment->write_index + rsize) % segment->size : 0;

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