/**
 *  Library for creating a shared memory ring buffer that can be used for the transmission of log messages 
 *  between a single writer and multiple readers. For more detail, see thesis chapter 3
 *  
 * 
 * 
 * 
 * 
*/


#ifndef _SHMRBUF_H
#define _SHMRBUF_H

#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <unistd.h>
#include <fcntl.h>
#include <threads.h>

#include <io_ipc.h>

#define SHMRBUF_PERM 0644 // File permission on the shared memory segment

// Flags
#define SHMRBUF_REATT 0x01 // Enables reattachment to an existing buffer for the writer (writer only)
#define SHMRBUF_FRCAT 0x02 // No current purpose
#define SHMRBUF_OVWR 0x04 // Enables overwrite for write operations to the buffer (writer only)
#define SHMRBUF_NOREG 0x08 // Enables a reader to attach to the buffer, without registering as a reader (for inspection purposes) (reader only)
#define SHMRBUF_RESET 0x016 // Resets the read pointers in all segments to the position of the writer, when reattaching as a reader 


// Writer parameters 
struct shmrbuf_writer_arg_t 
{
    const char * shm_key;
    uint16_t line_size;
    uint32_t line_count;
    uint8_t segment_count, reader_count;
    struct shmrbuf_global_hdr_t * global_hdr;
    struct shmrbuf_seg_whdr_t * segment_hdrs;
    int flags, shm_id;
};

// Reader parameters 
struct shmrbuf_reader_arg_t 
{
    const char * shm_key;
    int shm_id, flags;
    uint8_t reader_id;
    struct shmrbuf_global_hdr_t * global_hdr;
    struct shmrbuf_seg_rhdr_t * segment_hdrs;
};


// Global buffer information
struct shmrbuf_global_hdr_t 
{
    uint32_t checksum;
    uint8_t segment_count, reader_count;
    uint16_t line_size;
    uint32_t line_count;
    bool overwrite;
    atomic_bool writer_att , first_reader_att;
};

struct shmrbuf_seg_rhdr_t 
{
    atomic_uint_fast32_t * write_index, * read_index;
    pthread_mutex_t segment_lock;
    void * data;   
};

struct shmrbuf_seg_whdr_t 
{
    atomic_uint_fast32_t * write_index, * first_reader;
    void * data;  
};

// Possible, roles when calling shmrbuf_init or shmrbuf_finalize
enum shmrbuf_role_t 
{
    SHMRBUF_WRITER,
    SHMRBUF_READER
};

union shmrbuf_arg_t 
{
    struct shmrbuf_writer_arg_t wargs;
    struct shmrbuf_reader_arg_t rargs;
};

// Creates the ringbuffer or attaches to an existing one
int shmrbuf_init(union shmrbuf_arg_t * args,
                 enum shmrbuf_role_t role);

// Detaches from the ringbuffer and removes the  memory segment, if no other process is attached 
int shmrbuf_finalize(union shmrbuf_arg_t *,
                     enum shmrbuf_role_t role);

// Writes a single line to a segment
int shmrbuf_write(struct shmrbuf_writer_arg_t * args, 
                  void * src, uint16_t wsize, 
                  uint8_t segment_id);

// Writes multiple lines to a segment
int shmrbuf_writev(struct shmrbuf_writer_arg_t * args, 
                   struct iovec * iovecs, 
                   uint16_t vsize, 
                   uint8_t segment_id);

// Reads a single line from a segment
int shmrbuf_read(struct shmrbuf_reader_arg_t * args, 
                 void * rbuf, 
                 uint16_t bufsize, 
                 uint8_t segment_id);

// Reads multiple lines from a segment
int shmrbuf_readv(struct shmrbuf_reader_arg_t * args, 
                  struct iovec * iovecs, 
                  uint16_t vsize, 
                  uint16_t bufsize, 
                  uint8_t segment_id);

// Reads a line from a segment ouf of a specified range. 
int shmrbuf_read_rng(struct shmrbuf_reader_arg_t * args, 
                     void * rbuf, 
                     uint16_t bufsize, 
                     uint8_t lower, 
                     uint8_t upper, 
                     bool * wsteal);

// Reads multiple lines from a range of segments
int shmrbuf_readv_rng(struct shmrbuf_reader_arg_t * args, 
                      struct iovec * iovecs, 
                      uint16_t vsize, 
                      uint16_t bufsize, 
                      uint8_t lower, 
                      uint8_t upper, 
                      uint16_t * wsteal);

#endif