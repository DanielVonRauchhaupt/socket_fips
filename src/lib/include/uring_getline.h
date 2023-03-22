
#include <stdlib.h>
#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define LOGBUF_SIZE 256 * 100

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

char * uring_getline(struct file_io_t * fio_arg, uint32_t * lsize);
