#include "include/uring_getline.h"

static inline char * _rdline(u_int32_t * offset, uint32_t * rsize, char * buf, uint32_t * lsize)
{
    uint32_t start = *offset;

    while(*offset < *rsize)
    {
        if(buf[(*offset)++] == '\n') {break;}
    }

    while(buf[start] == '\0' && start < *offset) {start++;}

    *lsize = *offset - start;

    if(*offset == *rsize)
    {
        *offset = 0;
        *rsize = 0;
    }

    return &buf[start];
}

static inline void _rdstart(struct file_io_t * fio_arg, char * buf, uint32_t bufsize)
{
    if((fio_arg->sqe = io_uring_get_sqe(&fio_arg->ring)) != NULL)
    {
        io_uring_prep_read(fio_arg->sqe, fio_arg->logfile_fd, buf, bufsize, fio_arg->offset);
        if(io_uring_submit(&fio_arg->ring) < 0)
        {
            fio_arg->sqe = NULL;
        }
    }  
}

static inline bool _rdawait(struct file_io_t * fio_arg, char * buf, uint32_t bufsize, uint32_t * size)
{
    fio_arg->sqe = NULL;
    if(io_uring_wait_cqe(&fio_arg->ring, &fio_arg->cqe) < 0 || fio_arg->cqe->res < 0)
    {
        return false;
    }

    uint32_t rsize = (uint32_t) fio_arg->cqe->res;
    io_uring_cqe_seen(&fio_arg->ring, fio_arg->cqe);

    if((*size = rsize))
    {

        while(*size > 0)
        {
            if(buf[((*size)) - 1] == '\n') {break;}
            (*size)--;
        } 

        fio_arg->offset += *size;

        return rsize == bufsize;

    }

    return false;
}

char * uring_getline(struct file_io_t * fio_arg, uint32_t * lsize)
{

    if(fio_arg == NULL)
    {
        return NULL;
    }

    if(fio_arg->scnd_buf)
    {
        if(fio_arg->rsize2 > 0)
        {
            return _rdline(&fio_arg->offset2, &fio_arg->rsize2, fio_arg->fbuf2, lsize);
        }

        if(fio_arg->sqe != NULL)
        {
            if(_rdawait(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1), &fio_arg->rsize1))
            {
                _rdstart(fio_arg, fio_arg->fbuf2, sizeof(fio_arg->fbuf2));
            }
        }   

        else 
        {
            _rdstart(fio_arg, fio_arg->fbuf2, sizeof(fio_arg->fbuf2));
            if(_rdawait(fio_arg, fio_arg->fbuf2, sizeof(fio_arg->fbuf2), &fio_arg->rsize2))
            {
                _rdstart(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1));
            }

            if(fio_arg->rsize2 > 0)
            {
                return _rdline(&fio_arg->offset2, &fio_arg->rsize2, fio_arg->fbuf2, lsize);
            }

            return NULL;

        }

        if(fio_arg->rsize1 > 0)
        {
            fio_arg->scnd_buf = false;
            return _rdline(&fio_arg->offset1, &fio_arg->rsize1, fio_arg->fbuf1, lsize);
        }

        return NULL;

    }
    else 
    {
        if(fio_arg->rsize1 > 0)
        {
            return _rdline(&fio_arg->offset1, &fio_arg->rsize1, fio_arg->fbuf1, lsize);
        }

        if(fio_arg->sqe != NULL)
        {
            if(_rdawait(fio_arg, fio_arg->fbuf2, sizeof(fio_arg->fbuf2), &fio_arg->rsize2))
            {
                _rdstart(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1));
            }
        }   

        else 
        {
            _rdstart(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1));

            if(_rdawait(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1), &fio_arg->rsize1))
            {
                _rdstart(fio_arg, fio_arg->fbuf2, sizeof(fio_arg->fbuf2));
            }

            if(fio_arg->rsize1 > 0)
            {
                return _rdline(&fio_arg->offset1, &fio_arg->rsize1, fio_arg->fbuf1, lsize);
            }

            return NULL;

        }

        if(fio_arg->rsize2 > 0)
        {
            fio_arg->scnd_buf = true;
            return _rdline(&fio_arg->offset2, &fio_arg->rsize2, fio_arg->fbuf2, lsize);
        }

        return NULL;
    }

}
