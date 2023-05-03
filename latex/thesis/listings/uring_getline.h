/**
 *  io_uring based functions for reading lines from a file. 
 *  
 * 
 * 
*/

#ifndef _URING_GETLINE_H
#define _URING_GETLINE_H
#include <stdlib.h>
#include <fcntl.h>
#include <liburing.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <io_ipc.h>

#define BUFSIZE 1024 // Size of the read buffers in file_io_t
#define MAX_LINE 65535 // Maximum size of a line that can be read

/**
 * Structure to store file information,
 * buffered data and state across function calls
 * 
*/
struct file_io_t 
{
	int logfile_fd;
	off_t offset;
    struct io_uring ring;
    bool scnd_buf;
    struct io_uring_sqe * sqe;
    struct io_uring_cqe * cqe;
    uint32_t offset1, offset2;
    uint32_t rsize1, rsize2;
	char fbuf1[BUFSIZE];
	char fbuf2[BUFSIZE];
};

/**
 * Reads a single line from the file descriptor in file_io_t
 * On success, the function returns the size of the line in 
 * bytes and lineptr is set to the start if the line within
 * the buffer in file_io_t. If the file is empty, zero is 
 * returned. On error, the function returns an error code
 * (see io_ipc.h) 
*/
int uring_getline(struct file_io_t * fio_arg, 
                  char ** lineptr);

/**
 * Reads up to vsize lines from the file descriptor in file_io_t
 * On success, the function returns the number of lines read 
 * and copies the lines to the respective buffers in iovecs.
 * The len filed in the iovec struct is set to the length of the
 * respective line. If the file is empty, zero is 
 * returned. On error, the function returns an error code
 * (see io_ipc.h) 
*/
int uring_getlines(struct file_io_t * fio_arg, 
                   struct iovec * ivoecs, 
                   uint16_t vsize, 
                   uint16_t bufsize);

#endif