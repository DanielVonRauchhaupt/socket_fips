#define _GNU_SOURCE 
#include <stdio.h> 
#include <stdlib.h> 
#include <time.h> 
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <sys/uio.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <liburing.h>

// Local includes
#include <ip_to_str.h>
#include <io_ipc.h>
#include <shm_ringbuf.h>

// Configuration Options
#define DEFAULT_PORT 8080
#define DEFAULT_LOG "/mnt/scratch/PR/logs/udpsvr.log"
#define IP4_ADDRESS "10.3.10.131"
#define IP6_ADDRESS "2001:db8:db8::1" 
#define DOMAIN AF_INET
#define MT false
#define LOG_SHORT false

// Definitions
#define RETURN_SUC (0)
#define RETURN_FAIL (-1)

#define UNUSED(x)(void)(x)

#define HUGE_PAGE_SIZE 2048 * 1000

#define NEWLINE_CHAR (char) (10)
#define BLANK (char) (32)
#define INVALID_PAYLOAD ('B')

#define DATE_FMT "YYYY-MM-DD HH:MM:SS"
#define STRFTIME_FMT "%Y-%m-%d %H:%M:%S"
#define DATE_SIZE (sizeof(DATE_FMT) - 1)
#define STR_SIZE_IP4 (sizeof("DDD.DDD.DDD.DDD") - 1)
#define STR_SIZE_IP6 (sizeof("DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD") - 1)

#define LOG_STR_FMT_IP4 "YYYY-MM-DD HH:MM:SS client DDD.DDD.DDD.DDD exceeded request rate limit\n"
#define LOG_BUF_SIZE_IP4 (sizeof(LOG_STR_FMT_IP4) - 1)
#define LOG_STR_FMT_IP6 "YYYY-MM-DD HH:MM:SS client DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD exeeded request rate limit\n" 
#define LOG_BUF_SIZE_IP6 (sizeof(LOG_STR_FMT_IP6) - 1)
#define HOST_PREFIX " client "
#define HOST_PREFIX_SIZE (sizeof(HOST_PREFIX)-1)
#define MSG_STR " exceeded request rate limit\n"
#define MSG_STR_SIZE (sizeof(MSG_STR)-1)

#define OPEN_MODE O_WRONLY | O_CREAT | O_APPEND 
#define OPEN_PERM 0644

#define NANOSECONDS_PER_MILLISECOND 1000000
#define UTIL_TIMEOUT 500 * NANOSECONDS_PER_MILLISECOND

#define RECV_TIMEOUT 1000
#define MAX_MSG __IOV_MAX


// Global Variables
static char global_datetime_buf[DATE_SIZE+1];
static volatile sig_atomic_t server_running = true;
static pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t datebuf_lock = PTHREAD_RWLOCK_INITIALIZER;
static enum ipc_type_t ipc_type = SHM;

// Structs
struct packet_buf_t {
    struct mmsghdr msgs[MAX_MSG];
    struct iovec iovecs[MAX_MSG];
    unsigned char payload_buf[MAX_MSG];
};

struct disk_arg_t 
{
    int logfilefd;
    struct io_uring * ring;
    struct iovec iovecs[MAX_MSG];
    struct io_uring_sqe * sqe;
    struct io_uring_cqe * cqe;
};

struct sock_targ_t {
    int domain;
    uint8_t thread_id;
    void * ipc_arg;
    in_port_t port;
    uint64_t pkt_in;
    uint64_t pkt_out;
    uint64_t log_count;
    char strerror_buf[64];
    int return_code;
};

struct util_targ_t {
    size_t interval;
    int return_code;
};

// Helper functions

/* Prints a formatted string to a mutex locked file descriptor */
void sync_message(const char * fmt, pthread_mutex_t * lock, FILE * fp, va_list targs){
    pthread_mutex_lock(lock);
    vfprintf(fp, fmt, targs);
    pthread_mutex_unlock(lock);
}

/* Prints a formatted message to stdout (Thread safe) */
void info_msg(const char* fmt,...){
    va_list targs;
    va_start(targs, fmt);
    sync_message(fmt,&stdout_lock,stdout,targs);
    va_end(targs);
}

/* Prints a formatted message to stderr (Thread safe) */
void error_msg(const char * fmt,...){
    va_list targs;
    va_start(targs, fmt);
    sync_message(fmt,&stderr_lock,stderr,targs);
    va_end(targs);
}

/* Updates the global datetime buffer and returns timestamp (Thread safe) */
time_t update_datetime(char * datebuf){
    struct tm tm;
    time_t t = time(NULL);
    localtime_r(&t,&tm);
    if(pthread_rwlock_wrlock(&datebuf_lock)){
        pthread_rwlock_unlock(&datebuf_lock);
        return RETURN_FAIL;
    }
    strftime(datebuf,DATE_SIZE+1,STRFTIME_FMT,&tm);
    pthread_rwlock_unlock(&datebuf_lock);
    return t;
}

void ipc_cleanup(void * ipc_arg,enum ipc_type_t ipc_type, int * retval){

    switch (ipc_type)
    {
    case DISK:
        close(((struct disk_arg_t *)ipc_arg)->logfilefd);
        io_uring_queue_exit(((struct disk_arg_t *)ipc_arg)->ring);
        free(ipc_arg);
        return;
    
    case SHM:
        if(retval != NULL){
            *retval = shm_rbuf_finalize((struct shm_rbuf_arg_t *)ipc_arg);
        } else {
            shm_rbuf_finalize((struct shm_rbuf_arg_t *)ipc_arg);
        }
        free(ipc_arg);
        return;

    default:
        return;
    }

}

/* Blocks all blockable signals with the option to keep SIGINT and SIGTERM unblocked */
int8_t block_signals(bool keep){
    sigset_t set;
    if(sigfillset(&set)){
        return RETURN_FAIL;
    }

    if(keep){
        if(sigdelset(&set,SIGINT) || sigdelset(&set,SIGTERM)){
            return RETURN_FAIL;
        }
    }

    if(pthread_sigmask(SIG_BLOCK, &set, NULL)){
        return RETURN_FAIL;
    }

    return RETURN_SUC;
}

/* Hander for SIGINT and SIGTERM, sets running global to false */
void sig_handler(int signal){
    UNUSED(signal);
    server_running = false;
}

/* Routine for helper thread to periodically wake up and update the 
 global datetime buffer */
void * util_thread_routine(void * arg){

    if(block_signals(true)){
        error_msg("Failed to block signals\n");
    }
    if(signal(SIGINT,sig_handler) == SIG_ERR || signal(SIGTERM,sig_handler) == SIG_ERR){
        char strerror_buf[64];
        error_msg("Failed to set signal handler : %s\n",strerror_r(errno,strerror_buf,64));
    }

    struct util_targ_t * targs = (struct util_targ_t *) arg;
    struct timespec ts = {.tv_nsec=targs->interval};

    while (server_running)
    {
        if(update_datetime(global_datetime_buf) == -1){
            error_msg("Failed to updated datetime buffer\n");
        }

        nanosleep(&ts,NULL);

    }

    targs->return_code = RETURN_SUC;
    return &targs->return_code;
}

/* Copies the string form of addr to the logstr_buf */
uint8_t logstr_short(int domain, char * logstr_buf, void * addr){
    int addrlen;  
    if (domain == AF_INET){
        addrlen = ipv4_to_str((void *)&((struct sockaddr_in *)addr)->sin_addr,(void *)(logstr_buf));
    } else {
        addrlen = ipv6_to_str((void *)&((struct sockaddr_in6 *)addr)->sin6_addr,(void *)(logstr_buf));
    }
    logstr_buf[addrlen] = NEWLINE_CHAR;
    return addrlen + 1;
}

/* Writes a logstring to to logstr_addr */
uint8_t logstr_long(int domain, char * logstr_buf, struct sockaddr * addr){

    int logbufsize, max_addrlen, addrlen;
      

    if(pthread_rwlock_rdlock(&datebuf_lock)){
        pthread_rwlock_unlock(&datebuf_lock);
        return 0;
    }

    if(memcpy(logstr_buf,global_datetime_buf,DATE_SIZE) == NULL){
        pthread_rwlock_unlock(&datebuf_lock);
        return 0;
    }

    if(pthread_rwlock_unlock(&datebuf_lock)){
        return 0;
    }

    if(memcpy(logstr_buf+DATE_SIZE,HOST_PREFIX,HOST_PREFIX_SIZE) == NULL){
        return 0;
    }

    switch (domain)
    {
    case AF_INET:
        logbufsize = LOG_BUF_SIZE_IP4;
        max_addrlen = STR_SIZE_IP4;
        addrlen = ipv4_to_str((void *)&((struct sockaddr_in *)addr)->sin_addr,(void *)(logstr_buf + DATE_SIZE + HOST_PREFIX_SIZE));
        break;
    
    case AF_INET6:
        logbufsize = LOG_BUF_SIZE_IP6;
        max_addrlen = STR_SIZE_IP6;
        addrlen = ipv6_to_str((void *)&((struct sockaddr_in6 *)addr)->sin6_addr,(void *)(logstr_buf + DATE_SIZE + HOST_PREFIX_SIZE));
        break;

    default:
        return 0;
    }

    if(memcpy(logstr_buf+DATE_SIZE+HOST_PREFIX_SIZE+addrlen,MSG_STR,MSG_STR_SIZE) == NULL){
        return 0;
    }

    return logbufsize - (max_addrlen-addrlen);
}

/* Binds a socket to the provided address and port for a given domain */
int bind_socket(int sockfd, struct sockaddr * sockaddr, in_port_t port, int domain){

    socklen_t len;

    port = (port > 1023) ? port : DEFAULT_PORT;

    switch (domain)
    {
    case AF_INET:
        len = sizeof(struct sockaddr_in);
        ((struct sockaddr_in *)(sockaddr))->sin_port = htons(port);
        break;

    case AF_INET6:
        len = sizeof(struct sockaddr_in6);
        ((struct sockaddr_in *)(sockaddr))->sin_port = htons(port);
        break;
    
    default:
        return RETURN_FAIL;
    }

    if(bind(sockfd,sockaddr,len)){
        return RETURN_FAIL;
    }

    return RETURN_SUC;
}

/* Listen for udp packets. Replies to valid requests and logs invalid requests using ipc method specified by ipy_type*/
int listen_and_reply(int sockfd,struct sock_targ_t * targs){

    struct packet_buf_t * recvbuf = NULL;
    struct packet_buf_t * sendbuf = NULL;
    char * logstr_buf = NULL;
    void * recv_ipbuf = NULL;
    void * send_ipbuf = NULL;
    int retval_rcv, retval_snd, retval_ipc, i, send_count = 0, invalid_count = 0, logbuf_size, ip_bufsize;
    uint8_t logstr_len;

    if(targs->domain == AF_INET){
        ip_bufsize = sizeof(struct sockaddr_in);
        logbuf_size = LOG_BUF_SIZE_IP4;
    } else{
        ip_bufsize = sizeof(struct sockaddr_in6);
        logbuf_size = LOG_BUF_SIZE_IP6;
    }

    if((recvbuf = (struct packet_buf_t *) aligned_alloc(64,sizeof(struct packet_buf_t))) == NULL
        || (sendbuf = (struct packet_buf_t *) aligned_alloc(64,sizeof(struct packet_buf_t))) == NULL
        || (logstr_buf = (char *) aligned_alloc(64,logbuf_size*MAX_MSG)) == NULL 
        || (recv_ipbuf = aligned_alloc(64,ip_bufsize*MAX_MSG)) == NULL
        || (send_ipbuf = aligned_alloc(64,ip_bufsize*MAX_MSG)) == NULL) {
            error_msg("Memory allocation failed : %s",strerror_r(errno,targs->strerror_buf,sizeof(targs->strerror_buf)));
            free(sendbuf);
            free(logstr_buf);
            free(recv_ipbuf);
            free(send_ipbuf);
            return RETURN_FAIL;
        }

    if(memset(&recvbuf->msgs,0,sizeof(recvbuf->msgs)) == NULL
        || memset(&sendbuf->msgs,0,sizeof(sendbuf->msgs)) == NULL){
        error_msg("Memset error\n");
    }

    for(i = 0; i < MAX_MSG; i++){
        recvbuf->iovecs[i].iov_base = &recvbuf->payload_buf[i];
        recvbuf->iovecs[i].iov_len = 1;
        recvbuf->msgs[i].msg_hdr.msg_iov = &recvbuf->iovecs[i];
        recvbuf->msgs[i].msg_hdr.msg_iovlen = 1;
        recvbuf->msgs[i].msg_hdr.msg_name = (void *)((char *)(recv_ipbuf)+i*ip_bufsize);
        recvbuf->msgs[i].msg_hdr.msg_namelen = ip_bufsize;
        sendbuf->iovecs[i].iov_base = &sendbuf->payload_buf[i];
        sendbuf->iovecs[i].iov_len = 1;
        sendbuf->msgs[i].msg_hdr.msg_iov = &sendbuf->iovecs[i];
        sendbuf->msgs[i].msg_hdr.msg_iovlen = 1;
        sendbuf->msgs[i].msg_hdr.msg_name = (void *)((char *)(send_ipbuf)+i*ip_bufsize);
        sendbuf->msgs[i].msg_hdr.msg_namelen = ip_bufsize;

        if(ipc_type == DISK){
            ((struct disk_arg_t *)targs->ipc_arg)->iovecs[i].iov_base = &logstr_buf[i*logbuf_size];
            ((struct disk_arg_t *)targs->ipc_arg)->iovecs[i].iov_len = logbuf_size;
        }

    }

    while(server_running){

        retval_rcv = recvmmsg(sockfd,recvbuf->msgs,MAX_MSG,MSG_WAITALL,NULL);

        if (retval_rcv < 1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
			} else {
                error_msg("Error in recvmmsg : %s\n",strerror_r(errno,targs->strerror_buf,sizeof(targs->strerror_buf)));
                free(sendbuf);
                free(recvbuf);
                free(logstr_buf);
                free(recv_ipbuf);
                free(send_ipbuf);
                return RETURN_FAIL;
            }
			
		}

        targs->pkt_in += retval_rcv;

        // Check if previos io_uring submission was successful
        if(ipc_type == DISK && ((struct disk_arg_t *)targs->ipc_arg)->sqe!= NULL){

            struct disk_arg_t * disk_args = ((struct disk_arg_t *)targs->ipc_arg);
            
            if(((retval_ipc = io_uring_wait_cqe(disk_args->ring,&disk_args->cqe)) < 0) || (disk_args->cqe->res < 0)){
                error_msg("Error in io_uring write : %s\n",strerror_r(errno,targs->strerror_buf,sizeof(targs->strerror_buf)));
                free(sendbuf);
                free(recvbuf);
                free(logstr_buf);
                free(recv_ipbuf);
                free(send_ipbuf);
                return RETURN_FAIL;
            }

            io_uring_cqe_seen(disk_args->ring, disk_args->cqe);
            
        }


 
        for(i = 0; i < retval_rcv; i++){

            if(recvbuf->payload_buf[i] == INVALID_PAYLOAD){
                if((logstr_len = logstr_short(targs->domain,&logstr_buf[invalid_count*logbuf_size],(struct sockaddr *)recvbuf->msgs[i].msg_hdr.msg_name)) == 0){
                    error_msg("Error writing logstring\n");
                    continue;
                }

                switch (ipc_type)
                {
                case DISK:
                    ((struct disk_arg_t *)targs->ipc_arg)->iovecs[invalid_count++].iov_len = logstr_len;
                    break;
                   
                case SHM:
                   if((retval_ipc = shm_rbuf_write(((struct shm_rbuf_arg_t *)targs->ipc_arg),&logstr_buf[invalid_count*logbuf_size],logstr_len,targs->thread_id))!=IO_IPC_SUCCESS){
                        if(retval_ipc == IO_IPC_SIZE_ERR){
                            continue;
                        } 

                        else {
                            error_msg("Error in shm_rbuf_write : %s\n",strerror_r(errno,targs->strerror_buf,sizeof(targs->strerror_buf)));
                            free(sendbuf);
                            free(recvbuf);
                            free(logstr_buf);
                            free(recv_ipbuf);
                            free(send_ipbuf);
                            return RETURN_FAIL;
                        }
                   }

                   invalid_count++;

                default:
                    break;
                }

                continue;
            }

            sendbuf->msgs[send_count].msg_hdr.msg_name = recvbuf->msgs[i].msg_hdr.msg_name;
            sendbuf->payload_buf[send_count] = recvbuf->payload_buf[i] + 1;

            send_count++;

        }   

        if(invalid_count){

            switch (ipc_type)
            {
            case DISK:

                ((struct disk_arg_t *)targs->ipc_arg)->sqe = io_uring_get_sqe(((struct disk_arg_t *)targs->ipc_arg)->ring);

                io_uring_prep_writev(((struct disk_arg_t *)targs->ipc_arg)->sqe,((struct disk_arg_t *)targs->ipc_arg)->logfilefd,((struct disk_arg_t *)targs->ipc_arg)->iovecs,invalid_count,0);

                if(io_uring_submit(((struct disk_arg_t *)targs->ipc_arg)->ring) < 0){
                    error_msg("Error in io_uring submit : %s\n",strerror_r(errno,targs->strerror_buf,sizeof(targs->strerror_buf)));
                    free(sendbuf);
                    free(recvbuf);
                    free(logstr_buf);
                    free(recv_ipbuf);
                    free(send_ipbuf);
                return RETURN_FAIL;
                }
                
                break;
            
            default:
                break;
            }

            targs->log_count += invalid_count;

        }

        if(send_count){

            retval_snd = sendmmsg(sockfd,recvbuf->msgs,send_count,0);

            if(retval_snd < 1){

                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    error_msg("Error in sendmmsg : sendcount %d, %s\n",strerror_r(errno,targs->strerror_buf,sizeof(targs->strerror_buf)));
                    free(sendbuf);
                    free(recvbuf);
                    free(logstr_buf);
                    free(recv_ipbuf);
                    free(send_ipbuf);
                    return RETURN_FAIL;
                }
            } else {
                targs->pkt_out += retval_snd;
            }

        }
     
        send_count = 0;
        invalid_count = 0;
    }  

    return RETURN_SUC;
}

/* Routine for socket threads. Opens a socket and listens for incoming packets */
void * run_socket(void *args){

    int sockfd;
    int opt = 1;
    struct timeval timeout = {.tv_sec=0,.tv_usec=RECV_TIMEOUT};
    struct sock_targ_t * targs = (struct sock_targ_t *) args;
    struct sockaddr_storage server_addr;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(targs->thread_id,&cpuset);

    if(pthread_setaffinity_np(pthread_self(),sizeof(cpuset),&cpuset)){
        error_msg("Failed to set cpu affinity of thread %d to cpu %d\n",pthread_self(),targs->thread_id);
    }

    if(block_signals(false)){
        error_msg("Failed to block signals\n");
    }

    if ((sockfd = socket(targs->domain, SOCK_DGRAM, IPPROTO_UDP)) < 0) { 
        error_msg("Could not open socket : %s\n",strerror_r(errno,targs->strerror_buf,sizeof(targs->strerror_buf)));
        targs->return_code = RETURN_FAIL;
        return &targs->return_code;
    } 

    if(setsockopt(sockfd,SOL_SOCKET,SO_REUSEPORT,(void*)&opt,sizeof(opt))){
        error_msg("Cant set socket option SO_REUSEPORT : %s\n",strerror_r(errno,targs->strerror_buf,sizeof(targs->strerror_buf)));
        close(sockfd);
        targs->return_code = RETURN_FAIL;
        return &targs->return_code;
    }

    if(setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,(void*)&timeout,sizeof(timeout))){
        error_msg("Cant set socket option SO_RCVTIMEO : %s\n",strerror_r(errno,targs->strerror_buf,sizeof(targs->strerror_buf)));
        close(sockfd);
        targs->return_code = RETURN_FAIL;
        return &targs->return_code;
    } 
        
    if(memset(&server_addr, 0, sizeof(server_addr)) == NULL){
        error_msg("Memset error\n");
    }

    server_addr.ss_family = targs->domain;
    
    switch (targs->domain)
    {
    case AF_INET:
        if(inet_pton(AF_INET,IP4_ADDRESS,(void *)&((struct sockaddr_in *)&server_addr)->sin_addr)!=1){
            error_msg("Could not set %s as address, default to INADDR_ANY\n",IP4_ADDRESS);
            ((struct sockaddr_in *)&server_addr)->sin_addr.s_addr = INADDR_ANY;
        }    
        break;

    case AF_INET6:
        if(inet_pton(AF_INET6,IP6_ADDRESS,(void *)&((struct sockaddr_in6 *)&server_addr)->sin6_addr)!=1){
            error_msg("Could not set %s as address, default to IN6ADDR_ANY\n",IP6_ADDRESS);
            ((struct sockaddr_in6 *)&server_addr)->sin6_addr = in6addr_any;
        }
        break;
    
    default:
        error_msg("Invalid domain : %d\n", targs->domain);
        targs->return_code = RETURN_FAIL;
        return &targs->return_code;
    }


    if((bind_socket(sockfd,(struct sockaddr *)&server_addr,targs->port,targs->domain) == RETURN_FAIL) ){
        error_msg("Failed to bind socket : %s\n",strerror_r(errno,targs->strerror_buf,sizeof(targs->strerror_buf)));
        close(sockfd);
        targs->return_code = RETURN_FAIL;
        return &targs->return_code;
    }
    
    if(server_addr.ss_family == AF_INET){
        if(listen_and_reply(sockfd,targs)){
            error_msg("Listen and reply failed\n");
            close(sockfd);
            targs->return_code = RETURN_FAIL;
            return &targs->return_code;
        }  
    } else {
        if(listen_and_reply(sockfd,targs)){
            error_msg("Listen and reply failed\n");
            close(sockfd);
            targs->return_code = RETURN_FAIL;
            return &targs->return_code;
        } 
    }

    close(sockfd);
    targs->return_code = RETURN_SUC;

    return &targs->return_code;

}

int main(int argc, char ** argv) { 

    in_port_t serv_port = (argc > 1) ? (uint16_t)strtol(argv[1],NULL,10) : DEFAULT_PORT;
    int i, retval, thread_count, n_procs = get_nprocs();
    thread_count = (MT && n_procs > 0) ? n_procs : 1;
    void * ipc_arg;
    pthread_t * threads;
    pthread_t util_thread;
    struct sock_targ_t * sock_targs;
    struct util_targ_t util_arg = {.interval=(size_t)UTIL_TIMEOUT};

    if((threads = calloc(sizeof(pthread_t),thread_count-1)) == NULL || (sock_targs = calloc(sizeof(struct sock_targ_t),thread_count)) == NULL){
        perror("Calloc failed");
        exit(EXIT_FAILURE);
    }

    for(i = 0; i < thread_count; i++){
        sock_targs[i].thread_id = i;
        sock_targs[i].domain = DOMAIN;
        sock_targs[i].port = serv_port;
        sock_targs[i].log_count = 0;
        sock_targs[i].pkt_in = 0;
        sock_targs[i].pkt_out = 0;
    }

    switch (ipc_type)
    {
    case DISK:
    
        if((ipc_arg = calloc(sizeof(int),1)) == NULL){
            perror("calloc failed");
            free(threads);
            free(sock_targs);
            exit(EXIT_FAILURE);
        }

        if((*((int *)ipc_arg) = open(DEFAULT_LOG,OPEN_MODE,OPEN_PERM)) < 0){
            free(threads);
            free(sock_targs);
            perror("opening logfile failed");
            exit(EXIT_FAILURE);
        }

        for(i = 0; i < thread_count; i++){
            if((sock_targs[i].ipc_arg = aligned_alloc(sizeof(struct disk_arg_t),1)) == NULL){
                perror("aligned alloc failed");
            }

            else if(memset(((struct disk_arg_t *)ipc_arg)->iovecs,0,MAX_MSG*sizeof(struct iovec)) == NULL){
                fprintf(stderr,"Memset error\n");
            }

            else if(io_uring_queue_init(MAX_MSG,((struct disk_arg_t *)sock_targs[i].ipc_arg)->ring,0)){
                perror("io_uring queue init failed");
            } else {
                ((struct disk_arg_t *)sock_targs[i].ipc_arg)->logfilefd = *((int *)ipc_arg);
                continue;
            }
            for(int j = i; j > -1; j--){
                free(sock_targs[i].ipc_arg);
            }
            close(*((int *) ipc_arg));
            free(threads);
            free(sock_targs);
            exit(EXIT_FAILURE);
        }

        break;

    case SHM:

        if((ipc_arg = calloc(sizeof(struct shm_rbuf_arg_t),1)) == NULL){
            perror("calloc failed");
            free(threads);
            free(sock_targs);
            exit(EXIT_FAILURE);
        }

        ((struct shm_rbuf_arg_t *)(ipc_arg))->create = true;
        ((struct shm_rbuf_arg_t *)(ipc_arg))->key_path = DEFAULT_LOG;
        ((struct shm_rbuf_arg_t *)(ipc_arg))->segment_count = thread_count;
        ((struct shm_rbuf_arg_t *)(ipc_arg))->size = HUGE_PAGE_SIZE;

        if((retval = shm_rbuf_init(((struct shm_rbuf_arg_t *)(ipc_arg)))) != IO_IPC_SUCCESS){
            if(retval > 0){
                fprintf(stderr,"Error code %d\n",retval);
                perror("shm_rbuf_init failed");
            }
            else {
                fprintf(stderr,"shm_rbuf_init failed : error code %d\n",retval);
            }
            free(ipc_arg);
            free(threads);
            free(sock_targs);
            exit(EXIT_FAILURE);
        }

        for(i = 0; i < thread_count; i++){
            sock_targs[i].ipc_arg = ipc_arg;
        }

        break;
    
    
    default:
        fprintf(stderr,"Invalid ipc type value %d\n",ipc_type);
        free(threads);
        free(sock_targs);
        exit(EXIT_FAILURE);
    }

    if(update_datetime(global_datetime_buf) == RETURN_FAIL){
        fprintf(stderr,"Initializing the global datetime buffer failed\n");
        ipc_cleanup(ipc_arg,ipc_type,NULL);
        free(threads);
        free(sock_targs);
        exit(EXIT_FAILURE);
    }

    
    if(pthread_create(&util_thread,NULL,util_thread_routine,(void*)&util_arg)){
        perror("Creating util thread failed");
        ipc_cleanup(ipc_arg,ipc_type,NULL);
        free(threads);
        free(sock_targs);
        exit(EXIT_FAILURE);
    }

    for(i = 1; i < thread_count; i++){

        if(pthread_create(&threads[i],NULL,run_socket,(void*)&sock_targs[i])){
            perror("Could not create listener thread");
        }
    }

   run_socket((void *)&sock_targs[0]);

   for(i = 1; i < thread_count; i++){
        if(pthread_join(threads[i],NULL)){
            perror("Pthread join failed");
        }
   }

   if(pthread_join(util_thread,NULL)){
        perror("Pthread join failed");
   }

    unsigned long long int total_in_count = 0 ,total_out_count = 0, total_log_count = 0;

   for(i = 0; i < thread_count; i++){
        if(sock_targs[i].return_code != RETURN_SUC){
            fprintf(stderr,"Thread %d returned with an error : error code %d\n",i+1,sock_targs[i].return_code);
        }

        printf("Thread %d : packets received  : %lu, packets sent  : %lu, messages logged : %lu\n",i,sock_targs[i].pkt_in,sock_targs[i].pkt_out,sock_targs[i].log_count);

        total_in_count += sock_targs[i].pkt_in;
        total_out_count += sock_targs[i].pkt_out;
        total_log_count += sock_targs[i].log_count;
   }

    printf("Total packets received : %llu, total packets sent : %llu, total messages logged : %llu\n",total_in_count,total_out_count,total_log_count);

   if(util_arg.return_code == RETURN_FAIL){
        fprintf(stderr,"Util thread returned an error\n");
   }

   ipc_cleanup(ipc_arg,ipc_type,&retval);

    if(retval !=  IO_IPC_SUCCESS){
        fprintf(stderr,"Error in ipc cleanup : error code %d\n",retval);
    }

   free(threads);
   //free(sock_targs);
   
    
   return EXIT_SUCCESS; 
}
