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
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <signal.h>

// Local includes
#include <ip_to_str.h>

// Configuration Options
#define DEFAULT_PORT 8080
#define DEFAULT_LOG "test.log" //"/mnt/scratch/PR/logs/udpsvr.log"
#define IPV4_ADDRESS "127.0.0.1"//"10.3.10.131"
#define IPV6_ADDRESS "::1"//"2001:db8::1" 
#define DOMAIN AF_INET
#define MT true
#define LOG_SHORT false

// Definitions
#define RETURN_SUC (0)
#define RETURN_FAIL (-1)

#define UNUSED(x) (void)(x)

#define NEWLINE_CHAR (char) (10)
#define BLANK (char) (32)
#define INVALID_PAYLOAD ('B')

#define DATE_FMT "YYYY-MM-DD HH:MM:SS"
#define STRFTIME_FMT "%Y-%m-%d %H:%M:%S"
#define DATE_SIZE (sizeof(DATE_FMT) - 1)
#define ADDR_SIZE_IPV4 (sizeof("DDD.DDD.DDD.DDD") - 1)
#define ADDR_SIZE_IPV6 (sizeof("DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD") - 1)

#define LOG_STR_FMT_IPV4 "YYYY-MM-DD HH:MM:SS client DDD.DDD.DDD.DDD exeeded request rate limit\n"
#define LOG_BUF_SIZE_IPV4 (sizeof(LOG_STR_FMT_IPV4) - 1)
#define LOG_STR_FMT_IPV6 "YYYY-MM-DD HH:MM:SS client DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD exeeded request rate limit\n" 
#define LOG_BUF_SIZE_IPV6 (sizeof(LOG_STR_FMT_IPV6) - 1)
#define HOST_PREFIX " client "
#define HOST_PREFIX_SIZE (sizeof(HOST_PREFIX)-1)
#define MSG_STR " exeeded request rate limit\n"
#define MSG_STR_SIZE (sizeof(MSG_STR)-1)

#define OPEN_MODE O_WRONLY | O_CREAT | O_APPEND 
#define OPEN_PERM S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH

#define NANOSECONDS_PER_MILLISECOND 1000000
#define INTERVAL 500 * NANOSECONDS_PER_MILLISECOND


// Global Variables
static char global_datetime_buf[DATE_SIZE+1];
static volatile sig_atomic_t server_running = true;
static pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t datebuf_lock = PTHREAD_RWLOCK_INITIALIZER;
static int logfile_fd;

// Structs
struct socktarg_t {
    int domain;
    in_port_t port;
    uint64_t pkt_in;
    uint64_t pkt_out;
    int return_code;
};

struct util_targ_t {
    size_t interval;
    int return_code;
};

// Helper functions

/* Prints a formatted string to a mutex locked file descriptor */
void sync_message(const char * fmt, pthread_mutex_t * lock, FILE * fp, va_list args){
    pthread_mutex_lock(lock);
    vfprintf(fp, fmt, args);
    pthread_mutex_unlock(lock);
}

/* Prints a formatted message to stdout (Thread safe) */
void info_msg(const char* fmt,...){
    va_list args;
    va_start(args, fmt);
    sync_message(fmt,&stdout_lock,stdout,args);
    va_end(args);
}

/* Prints a formatted message to stderr (Thread safe) */
void error_msg(const char * fmt,...){
    va_list args;
    va_start(args, fmt);
    sync_message(fmt,&stderr_lock,stderr,args);
    va_end(args);
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

/* Blocks all blockable signals with the option to keep SIGINT and SIGTERM unblocked */
void block_signals(bool keep){
    sigset_t set;
    sigfillset(&set);

    if(keep){
        sigdelset(&set,SIGINT);
        sigdelset(&set,SIGTERM);
    }

    pthread_sigmask(SIG_BLOCK, &set, NULL);
}

/* Hander for SIGINT and SIGTERM, sets running global to false */
void sig_handler(int signal){
    UNUSED(signal);
    server_running = false;
}

/* Routine for helper thread to periodically wake up and update the 
 globla datetime buffer */
void * util_thread_routine(void * arg){

    block_signals(true);
    signal(SIGINT,sig_handler);
    signal(SIGTERM,sig_handler);

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

/* Copies the string form of addr to the log_str_buf */
uint8_t log_str_short(int domain, char * log_str_buf, void * addr){
    int addrlen;  
    if (domain == AF_INET6){
        addrlen = ipv6_to_str(addr,(void *)(log_str_buf));
    } else {
        addrlen = ipv4_to_str(addr,(void *)(log_str_buf));
    }
    log_str_buf[addrlen] = NEWLINE_CHAR;
    return addrlen + 1;
}

/* Writes a logstring to to log_str_addr */
uint8_t log_str_long(int domain, char * log_str_buf, void * addr){

    int logbufsize, max_addrlen, addrlen;
      

    if(pthread_rwlock_rdlock(&datebuf_lock)){
        pthread_rwlock_unlock(&datebuf_lock);
        return 0;
    }

    if(memcpy(log_str_buf,global_datetime_buf,DATE_SIZE) == NULL){
        pthread_rwlock_unlock(&datebuf_lock);
        return 0;
    }

    if(pthread_rwlock_unlock(&datebuf_lock)){
        return 0;
    }

    if(memcpy(log_str_buf+DATE_SIZE,HOST_PREFIX,HOST_PREFIX_SIZE) == NULL){
        return 0;
    }

    switch (domain)
    {
    case AF_INET:
        logbufsize = LOG_BUF_SIZE_IPV4;
        max_addrlen = ADDR_SIZE_IPV4;
        addrlen = ipv4_to_str(addr,(void *)(log_str_buf + DATE_SIZE + HOST_PREFIX_SIZE));
        break;
    
    case AF_INET6:
        logbufsize = LOG_BUF_SIZE_IPV6;
        max_addrlen = ADDR_SIZE_IPV6;
        addrlen = ipv6_to_str(addr,(void *)(log_str_buf + DATE_SIZE + HOST_PREFIX_SIZE));
        break;

    default:
        return 0;
    }

    if(memcpy(log_str_buf+DATE_SIZE+HOST_PREFIX_SIZE+addrlen,MSG_STR,MSG_STR_SIZE) == NULL){
        return 0;
    }

    return logbufsize - (addrlen-max_addrlen);
}

/* Binds a socket to the provided address and port for a given domain */
int bind_socket(int sock_fd, struct sockaddr * sockaddr, in_port_t port, int domain){

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

    if(bind(sock_fd,sockaddr,len)){
        return RETURN_FAIL;
    }

    return RETURN_SUC;
}

/* Listen for ipv4 udp connections. Replies to valid requests and logs invalid requests */
int listen_and_reply_ipv4(int sock_fd,struct socktarg_t * args){

    socklen_t len = sizeof(struct sockaddr_in);
    struct sockaddr_in client_addr;
    char msg_buf = 0;
    char log_str_buf[LOG_BUF_SIZE_IPV4];
    uint8_t log_str_len;

    memset(&client_addr,0,len);

    while(server_running){

        recvfrom(sock_fd, &msg_buf, 1, MSG_WAITALL,&client_addr, &len); 

        args->pkt_in++;

        if(msg_buf == INVALID_PAYLOAD){
            if(LOG_SHORT){
                if((log_str_len = log_str_short(AF_INET,log_str_buf,(void*)&client_addr.sin_addr)) == 0){
                    error_msg("Could not create logstring\n");
                    memset(log_str_buf,0,sizeof(log_str_buf));
                } else {
                    write(1,log_str_buf,log_str_len);
                }

            } else {
                if((log_str_len = log_str_long(AF_INET,log_str_buf,(void*)&client_addr.sin_addr)) == 0){
                    error_msg("Could not create logstring\n");
                    memset(log_str_buf,0,sizeof(log_str_buf));
                } else {
                     write(1,log_str_buf,log_str_len);
                }
            }
            continue;
        }

        msg_buf++;

        sendto(sock_fd, &msg_buf, 1, MSG_CONFIRM,&client_addr, len); 
        args->pkt_out++;
    }  

    return RETURN_SUC;
}

/* Listen for ipv6 udp connections. Replies to valid requests and logs invalid requests */
int listen_and_reply_ipv6(int sockfd, struct socktarg_t * args){

    socklen_t len = sizeof(struct sockaddr_in6);
    struct sockaddr_in6 client_addr;
    char msg_buf = 0;
    char log_str_buf[LOG_BUF_SIZE_IPV6];
    uint8_t log_str_len;

    memset(&client_addr,0,len);

    while(server_running){
        recvfrom(sockfd, &msg_buf, 1,  MSG_WAITALL,&client_addr, &len);  

        args->pkt_in++;

        if(msg_buf == INVALID_PAYLOAD){
            if(LOG_SHORT){
                if((log_str_len = log_str_short(AF_INET6,log_str_buf,(void*)&client_addr.sin6_addr)) == 0){
                    error_msg("Could not create logstring\n");
                    memset(log_str_buf,0,sizeof(log_str_buf));
                } else {
                    write(1,log_str_buf,log_str_len);
                }

            } else {
                if((log_str_len = log_str_long(AF_INET6,log_str_buf,(void*)&client_addr.sin6_addr)) == 0){
                    error_msg("Could not create logstring\n");
                    memset(log_str_buf,0,sizeof(log_str_buf));
                } else {
                     write(1,log_str_buf,log_str_len);
                }
            }
            continue;
        }
    
        msg_buf++;

        sendto(sockfd, &msg_buf, 1, MSG_CONFIRM,&client_addr, len);

        args->pkt_out++;
    }  

    return RETURN_SUC;
}

/* Routine for socket threads. Opens a socket and listens for incoming pakets */
void * run_socket(void * args){

    int sock_fd;
    int opt = 1;
    struct socktarg_t * targs = (struct socktarg_t *) args;
    struct sockaddr_storage server_addr;

    block_signals(false);

    if ((sock_fd = socket(targs->domain, SOCK_DGRAM, 0)) < 0) { 
        error_msg("Could not open socket : %s\n",strerror(errno)); 
        targs->return_code = RETURN_FAIL;
        return &targs->return_code;
    } 

    if(setsockopt(sock_fd,SOL_SOCKET,SO_REUSEPORT,(void*)&opt,sizeof(opt))){
        error_msg("Cant set socket option : SO_REUSEPORT\n");
        close(sock_fd);
        targs->return_code = RETURN_FAIL;
        return &targs->return_code;
    }
        
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.ss_family = targs->domain;
    
    switch (targs->domain)
    {
    case AF_INET:
        if(inet_pton(AF_INET,IPV4_ADDRESS,(void *)&((struct sockaddr_in *)&server_addr)->sin_addr)!=1){
            ((struct sockaddr_in *)&server_addr)->sin_addr.s_addr = INADDR_ANY;
        }    
        break;

    case AF_INET6:
        if(inet_pton(AF_INET6,IPV6_ADDRESS,(void *)&((struct sockaddr_in6 *)&server_addr)->sin6_addr)!=1){
            ((struct sockaddr_in6 *)&server_addr)->sin6_addr = in6addr_any;
        }
        break;
    
    default:
        error_msg("Invalid domain : %d\n", targs->domain);
        targs->return_code = RETURN_FAIL;
        return &targs->return_code;
    }


    if((bind_socket(sock_fd,(struct sockaddr *)&server_addr,targs->port,targs->domain) == RETURN_FAIL) ){
        error_msg("Failed to bind socket : %s\n",strerror(errno));
        close(sock_fd);
        targs->return_code = RETURN_FAIL;
        return &targs->return_code;
    }
    
    if(server_addr.ss_family == AF_INET){
        if(listen_and_reply_ipv4(sock_fd,targs)){
            error_msg("Listen and reply failed\n");
            close(sock_fd);
            targs->return_code = RETURN_FAIL;
            return &targs->return_code;
        }  
    } else {
        if(listen_and_reply_ipv6(sock_fd,targs)){
            error_msg("Listen and reply failed\n");
            close(sock_fd);
            targs->return_code = RETURN_FAIL;
            return &targs->return_code;
        } 
    }

    close(sock_fd);
    targs->return_code = RETURN_SUC;

    return &targs->return_code;

}

int main(int argc, char ** argv) { 

    in_port_t serv_port = (argc > 1) ? (uint16_t)strtol(argv[1],NULL,10) : DEFAULT_PORT;
    int thread_count = (MT) ? get_nprocs() : 0;
    pthread_t * threads;
    pthread_t util_thread;
    struct socktarg_t * sock_targs;
    struct util_targ_t util_arg = {.interval=(size_t)INTERVAL};
    struct socktarg_t main_targ = {.domain=DOMAIN,.port=serv_port};


   if((logfile_fd = open(DEFAULT_LOG,OPEN_MODE,OPEN_PERM)) < 0){
        perror("Opening logfile failed");
        exit(EXIT_FAILURE);
   }

    if((threads = calloc(sizeof(pthread_t),thread_count-1)) == NULL || (sock_targs = calloc(sizeof(struct socktarg_t),thread_count-1)) == NULL){
        perror("Calloc failed");
        close(logfile_fd);
        exit(EXIT_FAILURE);
    }

    if(update_datetime(global_datetime_buf) == RETURN_FAIL){
        fprintf(stderr,"Initializing the global datetime buffer failed\n");
        close(logfile_fd);
        exit(EXIT_FAILURE);
    }

    
    if(pthread_create(&util_thread,NULL,util_thread_routine,(void*)&util_arg)){
        perror("Creating util thread failed");
        close(logfile_fd);
        exit(EXIT_FAILURE);
    }

    for(int i = 0; i < thread_count-1; i++){
        if(memcpy((void*)&sock_targs[i],&main_targ,sizeof(struct socktarg_t))==NULL){
            perror("Memcopy failed");
            exit(EXIT_FAILURE);
        }
        if(pthread_create(&threads[i],NULL,run_socket,(void*)&sock_targs[i])){
            perror("Could not create listener thread");
            exit(EXIT_FAILURE);
        }
    }

   run_socket((void *)&main_targ);

   for(int i = 0; i < thread_count; i++){
        pthread_join(threads[i],NULL);
   }

   pthread_join(util_thread,NULL);

   free(threads);
   close(logfile_fd);
    
   return EXIT_SUCCESS; 
}
