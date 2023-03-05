#include  <stdio.h>
#include <liburing.h>
#include <time.h>
#include <argp.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <shm_ringbuf.h>
#include <io_ipc.h>
#include <fcntl.h>
#include <unistd.h>

#define DEFAULT_LOG "logmsg.log"
#define OPEN_FLAGS O_WRONLY | O_CREAT | O_APPEND
#define OPEN_PERM 0644

#define QUEUE_SIZE 10

#include <stdio.h>
#include <stdlib.h>
#include <argp.h>

#define TESTSTRING "DD-MM-YYYY HH:MM:SS This is a rather long string that could be a standin for real world log meassage\n"

struct arguments {
    char *key;
    int static_flag;
    char *filename;
};

static struct argp_option options[] = {
    {"static", 's', 0, 0, "Use static ring buffer",0},
    {"filename", 'f', "FILENAME", 0, "Specify the logfile",0},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {

    struct arguments *arguments = state->input;

    switch (key) {
        case 's':
            arguments->static_flag = 1;
            break;
        case 'f':
            arguments->filename = arg;
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num == 0) {
                arguments->key = arg;
            } else {
                argp_usage(state);
            }
            break;
        case ARGP_KEY_END:
            if (arguments->key == NULL) {
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = {
    .options = options,
    .parser = parse_opt,
    .args_doc = "SHM_KEY",
    .doc = "Simple program for writing log messages from shared memory ring buffer to file"
};

void write_routine(const char * logfile){

    int logfile_fd;
    off_t offset;
    struct io_uring ring;
    struct io_uring_sqe * sqe;
    struct io_uring_cqe * cqe;
    struct iovec iovs[QUEUE_SIZE];
    char logstrbuf[QUEUE_SIZE][sizeof(TESTSTRING)-1];

    if((logfile_fd = open(logfile, OPEN_FLAGS, OPEN_PERM)) < 0)
    {
        perror("open failed");
        exit(EXIT_FAILURE);
    }

    if((offset = lseek(logfile_fd, 0, SEEK_END)) == -1){
        perror("lseek");
        close(logfile_fd);
        exit(EXIT_FAILURE);
    }

    printf("Offset %ld\n",offset);

    if(io_uring_queue_init(QUEUE_SIZE, &ring, 0) < 0)
    {
        perror("io_uring_queue_init failed");
        close(logfile_fd);
        exit(EXIT_FAILURE);
    }

    for(int i = 0; i < QUEUE_SIZE; i++){

        memcpy(logstrbuf[i],TESTSTRING,sizeof(TESTSTRING)-1);

        
        iovs[i].iov_base = logstrbuf[i];
        iovs[i].iov_len = sizeof(TESTSTRING)-1;

    }

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_writev(sqe, logfile_fd, iovs, QUEUE_SIZE, offset);
    io_uring_submit(&ring);

    
    if(io_uring_wait_cqe(&ring,&cqe) < 0)
    {
        perror("io_uring_wait_cqe");
        io_uring_queue_exit(&ring);
        close(logfile_fd);
        exit(EXIT_FAILURE);
    }

    if(cqe->res < 0)
    {
        perror("io_uring_wait_cqe");
        io_uring_queue_exit(&ring);
        close(logfile_fd);
        exit(EXIT_FAILURE);
    }

    io_uring_cqe_seen(&ring,cqe);

    
    io_uring_queue_exit(&ring);
    close(logfile_fd);

}

int main(int argc, char **argv) {

    struct arguments arguments = {
        .key = NULL,
        .static_flag = 0,
        .filename = "test.log",
    };

    if(argp_parse(&argp, argc, argv, 0, 0, &arguments) == ARGP_ERR_UNKNOWN)
    {
        exit(EXIT_FAILURE);
    }

    write_routine(arguments.filename);


}
