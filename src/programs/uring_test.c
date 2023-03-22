#include <stdlib.h>
#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <time.h>

#define LOGBUF_SIZE 256 * 100

#define DEFAULT_LOG "logmsg.log"
#define OPEN_FLAGS O_RDONLY
#define OPEN_PERM 0644


struct file_io_t {
	int logfile_fd;
	off_t offset;
    struct io_uring ring;
    bool scnd_buf;
    struct io_uring_sqe * sqe;
    struct io_uring_cqe * cqe;
    uint32_t offset1, offset2;
    uint32_t rsize1, rsize2;
	char fbuf1[LOGBUF_SIZE];
	char fbuf2[LOGBUF_SIZE];
};

static inline char * _rdline(u_int32_t * offset, uint32_t * rsize, char * buf, uint32_t * lsize)
{
    uint32_t start = *offset;

    while(*offset < *rsize)
    {
        if(buf[(*offset)++] == '\n') {break;}
    }

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

    *size = fio_arg->cqe->res;

    while(*size > 0)
    {
        if(buf[((*size)--) - 1] == '\n') {break;}
    } 

    fio_arg->offset += *size;

    io_uring_cqe_seen(&fio_arg->ring, fio_arg->cqe);

    return (uint32_t) fio_arg->cqe->res == bufsize;
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

            if(_rdawait(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1), &fio_arg->rsize2))
            {
                _rdstart(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1));
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


int main(void)
{

    struct file_io_t * io_arg;
    char * line;
    uint32_t line_size = 0;
    struct timespec ts = {.tv_nsec=0,.tv_sec=1};

    if((io_arg = calloc(sizeof(struct file_io_t), 1)) == NULL)
    {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    if((io_arg->logfile_fd = open(DEFAULT_LOG, OPEN_FLAGS, OPEN_PERM)) == -1)
    {
        perror("open");
        exit(EXIT_FAILURE);
    }

    if(io_uring_queue_init(2, &io_arg->ring, 0) < 0)
    {
        perror("io_uring_queue_init failed");
        exit(EXIT_FAILURE);
    }

    while(true)
    {
        if((line = uring_getline(io_arg, &line_size)) != NULL)
        {
            printf("line : %s, size : %d\n", line, line_size);
        }

        else
        {
            nanosleep(&ts,NULL);
        }

    }



}