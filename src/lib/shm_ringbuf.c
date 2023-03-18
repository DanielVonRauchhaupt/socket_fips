#include "include/shm_ringbuf.h"

#define MIN(a,b)((a > b) ? b : a)
#define MAX(a,b)((a > b) ? a : b)

static int shm_cleanup(union shmrbuf_arg_t * args, enum shmrbuf_role_t role){

    int retval;

    switch (role)
    {
    case SHMRBUF_READER:
        
        free(args->rargs.segment_hdrs);
        retval = shmdt(args->rargs.head);

        memset(args,0,sizeof(struct shmrbuf_reader_arg_t));
        
        return retval;
    
    case SHMRBUF_WRITER:

        free(args->wargs.segment_hdrs);
        retval = shmctl(args->wargs.shmid, IPC_RMID, NULL);

        memset(args,0,sizeof(struct shmrbuf_writer_arg_t));
        
        return retval;

    default:
        return IO_IPC_ARG_ERR;
    }

}

int shmrbuf_init(union shmrbuf_arg_t * args, enum shmrbuf_role_t role){

    if(args == NULL)
    {
        return IO_IPC_NULLPTR_ERR;
    }

    key_t key = -1;
    int shm_flag = 0, shmid;
    size_t size = 0;
    struct shmrbuf_global_hdr_t * global_hdr;
    struct shmrbuf_seg_hdr_t * segment_hdrs;

    switch (role)
    {
    case SHMRBUF_WRITER:
        
        if(args->wargs.shm_key == NULL ||
           args->wargs.line_size == 0 ||
           args->wargs.lines == 0 ||
           args->wargs.segment_count == 0 ||
           args->wargs.reader_count == 0)
        {
            return IO_IPC_ARG_ERR;
        }

        key = ftok(args->wargs.shm_key,0);
        shm_flag = SHMRBUF_FLAGS;
        size = sizeof(struct shmrbuf_global_hdr_t) +
               args->wargs.segment_count * (args->wargs.lines * args->wargs.line_size +
               (args->wargs.reader_count + 1) * sizeof(atomic_uint_fast32_t));

        break;

    case SHMRBUF_READER:
        
        if(args->rargs.shm_key == NULL)
        {
            return IO_IPC_ARG_ERR;
        }

        key = ftok(args->wargs.shm_key,0);

        break;
    
    default:
        return IO_IPC_ARG_ERR;
    }

    if(key == -1)
    {
        return errno;
    }

    if(size <= PAGESIZE || (shmid = shmget(key,size, shm_flag | SHM_HUGETLB)) == -1)
    {
        if((shmid = shmget(key,size,shm_flag)) == -1)
        {
            return errno;
        }
    }

    if((global_hdr = (struct shmrbuf_global_hdr_t *) shmat(shmid,NULL,0)) == (void *) -1)
    {
        int reval = errno;
        shm_cleanup(args, role);
        return errno;
    }

    if(role == SHMRBUF_WRITER){

        global_hdr->lines = args->wargs.lines;
        global_hdr->line_size = args->wargs.line_size;
        global_hdr->segment_count = args->wargs.segment_count;
        global_hdr->reader_count = args->wargs.reader_count;
        global_hdr->overwrite = args->wargs.overwrite;
        args->wargs.head = global_hdr;
        args->wargs.shmid = shmid;

        if((args->wargs.segment_hdrs = (struct shmrbuf_seg_whdr_t *) calloc(sizeof(struct shmrbuf_seg_whdr_t),global_hdr->segment_count)) == NULL){
            shm_cleanup(args, role);
            return IO_IPC_MEM_ERR;
        }

    }  
    
    else {

        if(global_hdr->segment_count == 0 || global_hdr->lines == 0 || global_hdr->line_size == 0){  
            shm_cleanup(args, role);
            return IO_IPC_ARG_ERR;
        }   

        args->rargs.head = global_hdr;
        args->rargs.shmid = shmid;

        if((args->rargs.reader_index = atomic_fetch_add(&global_hdr->reader_index,1)) >= global_hdr->reader_count){
            shm_cleanup(args, role);
            return IO_IPC_ARG_ERR;
        }

        if((args->rargs.segment_hdrs = (struct shmrbuf_seg_rhdr_t *) calloc(sizeof(struct shmrbuf_seg_rhdr_t),global_hdr->segment_count)) == NULL){
            shm_cleanup(args, role);
            return IO_IPC_MEM_ERR;
        }


    }

    size_t offset = sizeof(struct shmrbuf_global_hdr_t), segment_size = sizeof(atomic_uint_fast32_t) * (global_hdr->reader_count + 1) + global_hdr->line_size * global_hdr->lines;


    for(int i = 0; i < global_hdr->segment_count; i++){

        atomic_uint_fast32_t * seg_head = (atomic_uint_fast32_t *)((char *)global_hdr + offset);

        if(role == SHMRBUF_WRITER){

            struct shmrbuf_seg_whdr_t * seg_whdr = &args->wargs.segment_hdrs[i];

            seg_whdr->write_index = seg_head;
            seg_whdr->first_reader = seg_head + 1;
            seg_whdr->data = (void *)(seg_head + 1 + global_hdr->reader_count);
        
            memset(seg_whdr->write_index,0,segment_size);

        } 

        else {
            
            struct shmrbuf_seg_rhdr_t * seg_rhdr = &args->rargs.segment_hdrs[i];

            seg_rhdr->write_index = seg_head;
            seg_rhdr->read_index = seg_head + (args->rargs.reader_index + 1);
            seg_rhdr->data = (void *)(seg_head + global_hdr->reader_count + 1);

        }

        offset += segment_size;

    }

    return IO_IPC_SUCCESS;

}


int shmrbuf_finalize(union shmrbuf_arg_t * args, enum shmrbuf_role_t role){

    if(args == NULL){
        return IO_IPC_NULLPTR_ERR;
    }

    return shm_cleanup(args, role);

}

int shmrbuf_write(struct shmrbuf_writer_arg_t * args, void * src, uint16_t wsize, uint8_t segment_id){

    if(args == NULL || src == NULL || args->segment_hdrs == NULL){
        return IO_IPC_NULLPTR_ERR;
    }

    else if(segment_id >= args->segment_count || wsize > args->line_size){
        return IO_IPC_ARG_ERR;
    }

    if(wsize == 0){
        return wsize;
    }

    struct shmrbuf_seg_whdr_t * segment = &args->segment_hdrs[segment_id];
    uint32_t write_index = atomic_load(segment->write_index);
    uint32_t new_write_index = (write_index == args->lines - 1) ? 0 : write_index + 1;

    if(!args->overwrite){

        for(int i = 0; i < args->reader_count; i++){
            if(new_write_index == atomic_load(segment->first_reader + i)){
                return IO_IPC_SIZE_ERR;
            }

        }

    }

    if(memcpy((char *)segment->data + write_index*args->line_size,src,wsize) == NULL){
        return IO_IPC_MEM_ERR;
    }

    atomic_store(segment->write_index,new_write_index);    

    return wsize;
}

int shmrbuf_read(struct shmrbuf_reader_arg_t * args, void * rbuf, uint16_t bufsize, uint8_t segment_id){

    if(args == NULL ||
       rbuf == NULL ||
       args->segment_hdrs == NULL){
        return IO_IPC_NULLPTR_ERR;
    }

    if(segment_id >= args->head->segment_count){
        return IO_IPC_ARG_ERR;
    }

    if(bufsize == 0){
        return bufsize;
    }

    struct shmrbuf_seg_rhdr_t * segment = &args->segment_hdrs[segment_id];
    uint32_t write_index = atomic_load(segment->write_index);

    if(pthread_mutex_lock(&segment->segment_lock) == -1){
        pthread_mutex_unlock(&segment->segment_lock);
        return IO_IPC_MUTEX_ERR;
    }

    uint32_t read_index = *segment->read_index;
    uint32_t new_read_index = (read_index == args->head->lines - 1) ? 0 : read_index + 1;
    uint16_t rsize = MIN(args->head->line_size,bufsize);

    if(write_index == read_index){

        if(pthread_mutex_unlock(&segment->segment_lock) == -1){
            return IO_IPC_MUTEX_ERR;
        }

        return 0;
    }

    if(memcpy(rbuf,(char*)segment->data + read_index * args->head->line_size,rsize) == NULL){
        return IO_IPC_MEM_ERR;
    }

    atomic_store(segment->read_index,new_read_index);   

    if(pthread_mutex_unlock(&segment->segment_lock) == -1){
        return IO_IPC_MUTEX_ERR;
    } 

    return rsize;

}