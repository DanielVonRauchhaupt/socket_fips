#define _GNU_SOURCE 1

#include <stdio.h> 
#include <stdlib.h> 
#include <time.h>
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <sys/sysinfo.h>
#include <arpa/inet.h> 
#include <stdbool.h>
#include <netinet/in.h> 
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/ip6.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <asm-generic/socket.h>
#include <signal.h>


// Local includes
#include <ip_to_str.h>
#include <ringbuf.h>
#include <ip_hashtable.h>

#define RETURN_SUC 0
#define RETURN_FAIL 1

#define UNUSED(x) (void)(x)

#define NEWLINE_CHAR (char) 10
#define DOT_CHAR (char) 46
#define COLON_CHAR (char) 58
#define BLANK 32


#define DATE_FMT "YYYY-MM-DD HH:MM:SS"
#define STRFTIME_FMT "%Y-%m-%d %H:%M:%S"
#define DATE_SIZE sizeof(DATE_FMT)
#define ADDR_SIZE_IPV4 sizeof("DDD.DDD.DDD.DDD")
#define ADDR_SIZE_IPV6 sizeof("DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD")

#define LOG_STR_FMT_IPV4 "YYYY-MM-DD HH:MM:SS DDD.DDD.DDD.DDD C\n"
#define LOG_BUF_SIZE_IPV4 sizeof(LOG_STR_FMT_IPV4)
#define LOG_STR_FMT_IPV6 "YYYY-MM-DD HH:MM:SS DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD:DDDD C\n"
#define LOG_BUF_SIZE_IPV6 sizeof(LOG_STR_FMT_IPV6)

#define OPEN_MODE O_WRONLY | O_CREAT | O_APPEND 
#define OPEN_PERM S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH

#define DEFAULT_PORT 8080
#define FALLBACK_PORT 8083
#define DEFAULT_LOG "test.log"//"/mnt/scratch/PR/udpsvr.log"
#define IPV4_ADDRESS "127.0.1.1" //"10.3.10.131"
#define IPV6_ADDRESS "2001:db8::1" 

#define RATE_LIMIT 1
#define INTERVAL 500 * NANOSECONDS_PER_MILLISECOND
#define NANOSECONDS_PER_MILLISECOND 1000000

// Global Variables1
static char global_datetime_buf[DATE_SIZE];
static volatile sig_atomic_t server_running = true;
static pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t datebuf_lock = PTHREAD_RWLOCK_INITIALIZER;
static struct ip_hashtable_t ip_htable;

static int logfile_fd = 1;

struct sock_targ_t {
    int domain;
    in_port_t port;
    int return_code;
};

struct util_targ_t {
    size_t interval;
    int return_code;
};

void info_msg(const char* msg){
    pthread_mutex_lock(&stdout_lock);
    fprintf(stdout,"%s\n",msg);
    pthread_mutex_unlock(&stdout_lock);
}

void error_msg(const char * msg){
    pthread_mutex_lock(&stderr_lock);
    fprintf(stderr,"%s : %s\n",msg,strerror(errno));
    pthread_mutex_unlock(&stderr_lock);
}

time_t update_datetime(char * datebuf){
    struct tm tm;
    time_t t = time(NULL);
    localtime_r(&t,&tm);
    if(pthread_rwlock_wrlock(&datebuf_lock)){
        pthread_rwlock_unlock(&datebuf_lock);
        return -1;
    }
    strftime(datebuf,DATE_SIZE,STRFTIME_FMT,&tm);
    pthread_rwlock_unlock(&datebuf_lock);
    return t;
}

void block_signals(bool keep){
    sigset_t set;
    sigfillset(&set);

    if(keep){
        sigdelset(&set,SIGINT);
        sigdelset(&set,SIGTERM);
    }

    pthread_sigmask(SIG_BLOCK, &set, NULL);
}

void sig_handler(int signal){
    UNUSED(signal);
    server_running = false;
}

void * signal_thread_routine(void * arg){
    UNUSED(arg);
    block_signals(true);
    sigset_t set;
    int sig;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);

    sigprocmask(SIG_BLOCK, &set, NULL);

    sigwait(&set, &sig);

    server_running = false;

    info_msg("Server shutting down");


    return NULL;
}

void * util_thread_routine(void * arg){

    block_signals(false);
    time_t new, old;
    old = time(NULL);
    struct util_targ_t * targs = (struct util_targ_t *) arg;
    struct timespec ts = {.tv_nsec=targs->interval};

    while (server_running)
    {
        new = update_datetime(global_datetime_buf);

        if((new - old) > 1){
            if(ip_hashtable_reset(&ip_htable)==_IP_HASHTABLE_FAIL_){
                targs->return_code = RETURN_FAIL;
                error_msg("Error while resetting ip connection cache");
            }
        }
        nanosleep(&ts,NULL);

    }

    targs->return_code = RETURN_SUC;
    return &targs->return_code;
}

int log_packet_info(int logfile_fd, int domain, char * log_str_buf, void * addr,char payload){
    int logbufsize = LOG_BUF_SIZE_IPV4, addrsize = ADDR_SIZE_IPV4;
    int addrlen;  
    pthread_rwlock_rdlock(&datebuf_lock);
    memcpy(log_str_buf,global_datetime_buf,DATE_SIZE-1);
    pthread_rwlock_unlock(&datebuf_lock);
    log_str_buf[DATE_SIZE-1] = BLANK;
    if (domain == AF_INET6){
        logbufsize = LOG_BUF_SIZE_IPV6;
        addrsize = ADDR_SIZE_IPV6;
        addrlen = ipv6_to_str(addr,(void *)(log_str_buf + DATE_SIZE));
    } else {
        addrlen = ipv4_to_str(addr,(void *)(log_str_buf + DATE_SIZE));
    }
    log_str_buf[DATE_SIZE+addrlen] = BLANK;
    log_str_buf[DATE_SIZE+addrlen+1] = payload;
    log_str_buf[DATE_SIZE+addrlen+2] = NEWLINE_CHAR;

    if(write(logfile_fd,log_str_buf,logbufsize+(addrlen-addrsize)) < 0){
        return RETURN_FAIL;
    }

    return RETURN_SUC;
}

int bind_socket(int sockfd, struct sockaddr * sockaddr, in_port_t port, int domain){
    socklen_t len = (domain == AF_INET6) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    in_port_t ports[] = {port,DEFAULT_PORT,FALLBACK_PORT};
    uint8_t i = (port >= 1024 && port != DEFAULT_PORT) ? 0 : 1;

    for(; i < sizeof(ports)/sizeof(in_port_t);i++){
        
        if(domain == AF_INET){
            ((struct sockaddr_in *)sockaddr)->sin_port = htons(ports[i]);
        } else if (domain == AF_INET6) {
            ((struct sockaddr_in6 *)sockaddr)->sin6_port = htons(ports[i]);
        } else {
            error_msg("Invalid domain");
            return RETURN_FAIL;
        }

        if(bind(sockfd,sockaddr,len) < 0 ){
            error_msg("Could not bind to port");
        } else {
            return RETURN_SUC;
        }
    }

    return RETURN_FAIL;
}

int listen_and_reply_ipv4(int sockfd){

    __socklen_t len = sizeof(struct sockaddr_in);
    struct sockaddr_in client_addr;
    char msg_buf = 0;
    char log_str_buf[LOG_BUF_SIZE_IPV4];
    uint32_t con_count;

    memset(&client_addr,0,len);

    while(server_running){
        recvfrom(sockfd, &msg_buf, 1, MSG_WAITALL,&client_addr, &len); 

        con_count = ip_hashtable_inc_v4(&ip_htable,(uint32_t *)&client_addr.sin_addr);

        if((con_count % RATE_LIMIT) == 0){
            log_packet_info(logfile_fd,AF_INET,log_str_buf,(void*)&client_addr.sin_addr,msg_buf);
            continue;
        }
    
        msg_buf += 1;

        sendto(sockfd, &msg_buf, 1, MSG_CONFIRM,&client_addr, len); 
    }  

    return RETURN_SUC;
}

int listen_and_reply_ipv6(int sockfd){

    __socklen_t len = sizeof(struct sockaddr_in6);
    struct sockaddr_in6 client_addr;
    char msg_buf = 0;
    char log_str_buf[LOG_BUF_SIZE_IPV6];
    uint32_t con_count;

    memset(&client_addr,0,len);

    while(server_running){
        recvfrom(sockfd, &msg_buf, 1,  MSG_WAITALL,&client_addr, &len);  

        con_count = ip_hashtable_inc_v6(&ip_htable,(__uint128_t *)&client_addr.sin6_addr);

        if((con_count % RATE_LIMIT) == 0){
            log_packet_info(logfile_fd,AF_INET6,log_str_buf,(void*)&client_addr.sin6_addr,msg_buf);
            continue;
        }
    
        msg_buf += 1;

        sendto(sockfd, &msg_buf, 1, MSG_CONFIRM,&client_addr, len);
    }  

    return RETURN_SUC;
}

void * run_socket(void * args){

    int sock_fd;
    int opt = 1;
    struct sock_targ_t * targs = (struct sock_targ_t *) args;
    struct sockaddr_storage server_addr;



    //block_signals(false);

    if ((sock_fd = socket(targs->domain, SOCK_DGRAM, 0)) < 0) { 
        error_msg("Could not open socket"); 
        targs->return_code = RETURN_FAIL;
        pthread_exit((void*)&targs->return_code);
    } 

    if(setsockopt(sock_fd,SOL_SOCKET,SO_REUSEPORT,(void*)&opt,sizeof(opt))){
        error_msg("Cant set SO_REUSEPORT");
        close(sock_fd);
        targs->return_code = RETURN_FAIL;
        pthread_exit((void*)&targs->return_code);
    }
        
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.ss_family = targs->domain;
    
    if(targs->domain == AF_INET){
        if(inet_pton(AF_INET,IPV4_ADDRESS,(void *)&((struct sockaddr_in *)&server_addr)->sin_addr)!=1){
            ((struct sockaddr_in *)&server_addr)->sin_addr.s_addr = INADDR_ANY;
        }      
    } 
    else if(targs->domain == AF_INET6){
        if(inet_pton(AF_INET6,IPV6_ADDRESS,(void *)&((struct sockaddr_in6 *)&server_addr)->sin6_addr)!=1){
            ((struct sockaddr_in6 *)&server_addr)->sin6_addr = in6addr_any;
        }      
    } else {
        error_msg("Invalid domain");
        targs->return_code = RETURN_FAIL;
        pthread_exit((void*)&targs->return_code);
    }

    if((bind_socket(sock_fd,(struct sockaddr *)&server_addr,targs->port,targs->domain) == RETURN_FAIL) ){
        error_msg("Failed to bind socket");
        close(sock_fd);
        targs->return_code = RETURN_FAIL;
        pthread_exit((void*)&targs->return_code);
    }
    
    if(listen_and_reply_ipv4(sock_fd) < 0){
        error_msg("Listen and reply failed");
        close(sock_fd);
        targs->return_code = RETURN_FAIL;
        pthread_exit((void*)&targs->return_code);
    }

    close(sock_fd);
    targs->return_code = RETURN_SUC;

    return &targs->return_code;

}

int main(int argc, char ** argv) { 

    in_port_t serv_port = (argc > 1) ? (uint16_t)strtol(argv[1],NULL,10) : DEFAULT_PORT;
    
    int thread_count = get_nprocs();
    pthread_t * threads;
    struct sock_targ_t * sock_targs;
    pthread_t util_thread;
    struct util_targ_t util_arg = {.interval=(size_t)INTERVAL};
    struct sock_targ_t main_targ = {.domain=AF_INET,.port=serv_port};

    if(ip_hashtable_init(&ip_htable,AF_INET)){
        error_msg("Initializing ip connection cache failed");
        exit(EXIT_FAILURE);
    }

   if((logfile_fd = open(DEFAULT_LOG,OPEN_MODE,OPEN_PERM)) < 0){
        error_msg("Open failed");
        exit(EXIT_FAILURE);
   }

    if((threads = calloc(sizeof(pthread_t),thread_count-1)) == NULL || (sock_targs = calloc(sizeof(struct sock_targ_t),thread_count-1)) == NULL){
        fprintf(stderr,"Calloc Error: %s\n",strerror(errno));
        close(logfile_fd);
        exit(EXIT_FAILURE);
    }

    update_datetime(global_datetime_buf);

    
    if(pthread_create(&util_thread,NULL,util_thread_routine,(void*)&util_arg)){
        error_msg("Failed to create utility thread");
        exit(EXIT_FAILURE);
    }

    for(int i = 0; i < thread_count-1; i++){
        memcpy((void*)&sock_targs[i],&main_targ,sizeof(struct sock_targ_t));
        if(pthread_create(&threads[i],NULL,run_socket,(void*)&sock_targs[i])){
            error_msg("Failed to create listener thread");
        }
    }

   run_socket((void *)&main_targ);

   for(int i = 0; i < thread_count; i++){
        pthread_join(threads[i],NULL);
   }


   pthread_join(util_thread,NULL);

   free(threads);
   close(logfile_fd);

   struct ip_hashtable_stats_t stats;

   if(ip_hashtable_gather_stats(&ip_htable,&stats)){
        error_msg("Error retreiving ip connection cache stats");
    } else {
        printf("Number of Clients serviced : %d, Total Connections : %ld\n",stats.client_count,stats.connection_count);
    }

   ip_hashtable_destroy(&ip_htable);
    
   return EXIT_SUCCESS; 
}
