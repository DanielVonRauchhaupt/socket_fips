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

#include "ip_to_str.h"
#include "ringbuf.h"

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
#define IPV4_ADDRESS "10.3.10.131"
#define IPV6_ADDRESS "2001:db8::1" 

// Global Variables
static char global_datetime_buf[DATE_SIZE];
static volatile sig_atomic_t server_running = true;
static pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t datetime_lock_rw = PTHREAD_RWLOCK_INITIALIZER;

static pthread_mutex_t buffer_lock = PTHREAD_MUTEX_INITIALIZER;

static FILE * logfile_fd;


struct sock_thread_arg_t {
    int sock_fd;
    int domain;
    in_port_t port;
    time_t time;
    struct ringbuf_t rbuf; 
    int return_code;
};

struct time_thread_arg_t {
    int interval;
    int return_code;
};

struct sig_thread_arg_t {
    int return_code;
};

void info_msg(const char* msg){
    pthread_mutex_lock(&stderr_lock);
    fprintf(stdout,"%s\n",msg);
    pthread_mutex_unlock(&stderr_lock);
}

void error_msg(const char * msg){
    pthread_mutex_lock(&stderr_lock);
    fprintf(stderr,"%s : %s\n",msg,strerror(errno));
    pthread_mutex_unlock(&stderr_lock);
}

void update_datetime(char * datebuf){
    struct tm tm;
    time_t t = time(NULL);
    localtime_r(&t,&tm);
    strftime(datebuf,DATE_SIZE,STRFTIME_FMT,&tm);
}


void sigint_handler(int signal){
    UNUSED(signal);
    server_running = false;
}

void * time_thread_routine(void * arg){

    while (server_running)
    {
        pthread_rwlock_wrlock(&datetime_lock_rw);
        update_datetime(global_datetime_buf);
        pthread_rwlock_unlock(&datetime_lock_rw);
        nanosleep((struct timespec *)(arg),NULL);
    }

    

    return NULL;
}


int log_packet_info_ipv4(int logfile_fd, char * log_str_buf, char * addr,char payload){
    memset(log_str_buf,BLANK,LOG_BUF_SIZE_IPV4-1);
    pthread_rwlock_rdlock(&datetime_lock_rw);
    memcpy(log_str_buf,global_datetime_buf,DATE_SIZE-1);
    pthread_rwlock_rdlock(&datetime_lock_rw);
    memcpy(log_str_buf+DATE_SIZE,addr,ADDR_SIZE_IPV4-1);
    memcpy(log_str_buf+DATE_SIZE+ADDR_SIZE_IPV4,&payload,1);

    if(write(logfile_fd,log_str_buf,LOG_BUF_SIZE_IPV4) < 0){
        return RETURN_FAIL;
    }

    return RETURN_SUC;
}

int log_packet_info_ipv6(int logfile_fd, char * log_str_buf, char * addr,char payload){
    memset(log_str_buf,BLANK,LOG_BUF_SIZE_IPV6-1);
    pthread_rwlock_rdlock(&datetime_lock_rw);
    memcpy(log_str_buf,global_datetime_buf,DATE_SIZE-1);
    pthread_rwlock_rdlock(&datetime_lock_rw);
    memcpy(log_str_buf+DATE_SIZE,addr,ADDR_SIZE_IPV6-1);
    memcpy(log_str_buf+DATE_SIZE+ADDR_SIZE_IPV6,&payload,1);

    if(write(logfile_fd,log_str_buf,LOG_BUF_SIZE_IPV6) < 0){
        return RETURN_FAIL;
    }

    return RETURN_SUC;
}

int bind_socket(int sockfd, struct sockaddr * sockaddr_ptr, in_port_t port, int domain){
    socklen_t len;
    in_port_t * port_ptr;
    in_port_t ports[] = {port,htons(DEFAULT_PORT),htons(FALLBACK_PORT)};
    size_t i = (port >= htons(1024) && port != htons(DEFAULT_PORT)) ? 0 : 1;

    if(domain == AF_INET){
        len = sizeof(struct sockaddr_in);
        port_ptr = &((struct sockaddr_in *)(sockaddr_ptr))->sin_port;
    } else {
        len = sizeof(struct sockaddr_in6);
        port_ptr = &((struct sockaddr_in6 *)(sockaddr_ptr))->sin6_port;
    }
    
    for(; i < sizeof(ports)/sizeof(in_port_t);i++){
        *port_ptr = ports[i];
        if(bind(sockfd,sockaddr_ptr,len) < 0 ){
            fprintf(stderr,"Could not bind at port: %d. %s\n",ntohs(*port_ptr),strerror(errno));
        } else {
            return RETURN_SUC;
        }
    }

    return RETURN_FAIL;
}

int listen_and_reply_ipv4(int sockfd, struct sockaddr_in * addr){

    __socklen_t len = sizeof(struct sockaddr_in);
    void * client_addr_ptr = (void *)&(addr->sin_addr);
    char msg_buf = 0;
    char addr_buf[INET_ADDRSTRLEN];
    char log_str_buf[LOG_BUF_SIZE_IPV4];
    int logfile_fd;

    if((logfile_fd = open(DEFAULT_LOG,O_CREAT,O_APPEND,O_WRONLY)) < 0){
        error_msg("Failed to open logfile");
        return RETURN_FAIL;
    }

    log_str_buf[LOG_BUF_SIZE_IPV4-1] = NEWLINE_CHAR;

    while(server_running){
        recvfrom(sockfd, &msg_buf, 1,  MSG_WAITALL, client_addr_ptr, &len);
        inet_ntop(AF_INET,client_addr_ptr,addr_buf,len);      
        log_packet_info_ipv4(logfile_fd,log_str_buf,addr_buf,(unsigned int)msg_buf);
        msg_buf += 1;
        sendto(sockfd, &msg_buf, 1, MSG_CONFIRM, client_addr_ptr, len); 
    }  

    close(logfile_fd);

    return RETURN_SUC;
}

int listen_and_reply_ipv6(int sockfd, struct sockaddr_in * addr){

    __socklen_t len = sizeof(struct sockaddr_in);
    void * client_addr_ptr = (void *)&(addr->sin_addr);
    char msg_buf = 0;
    char addr_buf[INET6_ADDRSTRLEN];
    char log_str_buf[LOG_BUF_SIZE_IPV6];
    int logfile_fd;

    if((logfile_fd = open(DEFAULT_LOG,O_CREAT,O_APPEND,O_WRONLY)) < 0){
        error_msg("Failed to open logfile");
        return RETURN_FAIL;
    }

    log_str_buf[LOG_BUF_SIZE_IPV6-1] = NEWLINE_CHAR;

    while(server_running){
        recvfrom(sockfd, &msg_buf, 1,  MSG_WAITALL, client_addr_ptr, &len);
        inet_ntop(AF_INET6,client_addr_ptr,addr_buf,len);      
        log_packet_info_ipv6(logfile_fd,log_str_buf,addr_buf,(unsigned int)msg_buf);
        msg_buf += 1;
        sendto(sockfd, &msg_buf, 1, MSG_CONFIRM, client_addr_ptr, len); 
    }  

    close(logfile_fd);

    return RETURN_SUC;
}

void * run_socket(void * args){

    int sock_fd;
    int opt = 1;
    struct sock_thread_arg_t * thread_args = (struct sock_thread_arg_t *) args;
    struct sockaddr server_addr, client_addr;


    if ((sock_fd = socket(thread_args->domain, SOCK_DGRAM, 0)) < 0) { 
        error_msg("Could not open socket"); 
        thread_args->return_code = RETURN_FAIL;
        pthread_exit((void*)&thread_args->return_code);
    } 

    if(setsockopt(sock_fd,SOL_SOCKET,SO_REUSEPORT,(void*)&opt,sizeof(opt))){
        error_msg("Cant set SO_REUSEPORT");
        close(sock_fd);
        thread_args->return_code = RETURN_FAIL;
        pthread_exit((void*)&thread_args->return_code);
    }
        
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));
    
    if(thread_args->domain == AF_INET){
        struct sockaddr_in * ipv4_addr_ptr = (struct sockaddr_in *)&server_addr;
        if(inet_pton(thread_args->domain,IPV4_ADDRESS,(void *) &ipv4_addr_ptr->sin_addr)!=1){
            ipv4_addr_ptr->sin_addr.s_addr = INADDR_ANY;
        }      
        ipv4_addr_ptr->sin_port = thread_args->port;
        ipv4_addr_ptr->sin_family = AF_INET;
    } 
    else{
        struct sockaddr_in6 * ipv6_addr_ptr = (struct sockaddr_in6 *)&server_addr;
        if(inet_pton(thread_args->domain,IPV6_ADDRESS,(void *) &ipv6_addr_ptr->sin6_addr)!=1){
            ipv6_addr_ptr->sin6_addr = in6addr_any;
        }      
        ipv6_addr_ptr->sin6_port = thread_args->port;
        ipv6_addr_ptr->sin6_family = AF_INET6;
    }
    

    if((bind_socket(sock_fd,&server_addr,thread_args->port,thread_args->domain) == RETURN_FAIL) ){
        error_msg("Failed to bind socket");
        close(sock_fd);
        thread_args->return_code = RETURN_FAIL;
        pthread_exit((void*)&thread_args->return_code);
    }
    
    if(listen_and_reply_ipv4(sock_fd,(struct sockaddr_in *) &client_addr) < 0){
        error_msg("Listen and reply failed");
        close(sock_fd);
        thread_args->return_code = RETURN_FAIL;
        pthread_exit((void*)&thread_args->return_code);
    }

    close(sock_fd);
    thread_args->return_code = RETURN_SUC;

    return &thread_args->return_code;

}


void * test_routine(void * arg){

    struct sock_thread_arg_t * t_arg = (struct sock_thread_arg_t *) arg;

    for(int i = 0; i < 1000*1000; i++){
        if(ringbuf_write(&t_arg->rbuf,LOG_STR_FMT_IPV4,LOG_BUF_SIZE_IPV4-1)==0){
            ringbuf_write_to_file(&t_arg->rbuf,logfile_fd);
        }
    }

    return NULL;

}


int main(int argc, char ** argv) { 

    /*
    in_port_t serv_port = (argc > 1) ? htons((uint16_t)strtol(argv[1],NULL,10)) : htons(DEFAULT_PORT);
    
    signal(SIGINT,sigint_hanlder);

    int thread_count = get_nprocs();
    pthread_t * threads;

    if((threads = calloc(sizeof(pthread_t),thread_count-1)) == NULL){
        fprintf(stderr,"Calloc Error: %s\n",strerror(errno));
        exit(EXIT_FAILURE);
    }

    for(int i = 0; i < thread_count; i++){
        pthread_create(&threads[i],NULL,run_socket,&serv_port);
    }

   run_socket(&serv_port);

   for(int i = 0; i < thread_count; i++){
        pthread_join(threads[i],NULL);
   }

   free(threads);
    */

   /*
   int fd = open(DEFAULT_LOG,OPEN_MODE,OPEN_PERM);

   if(fd < 0){
        error_msg("Open failed");
        exit(EXIT_FAILURE);
   }

   char logstrbuf[LOG_BUF_SIZE_IPV4];

   memset(logstrbuf,32,LOG_BUF_SIZE_IPV4-1);

   logstrbuf[LOG_BUF_SIZE_IPV4-1]='\n';

   memset(global_datetime_buf,0,DATE_SIZE);

   update_datetime(global_datetime_buf);

   char ip_buf[INET_ADDRSTRLEN+2];

   ip_buf[INET6_ADDRSTRLEN+1] = (char) 10;

   ip_buf[INET6_ADDRSTRLEN] = (char) 116;

   memset(ip_buf,32,INET6_ADDRSTRLEN);

   struct sockaddr_in6 ip_addr;

   inet_pton(AF_INET6,IPV6_ADDRESS,(void*)&ip_addr.sin6_addr);

   int offset = ipv6_to_str((void *) &ip_addr.sin6_addr,ip_buf);

    write(1,ip_buf,offset);
    write(1,"\n",1);
    */
    /*
   if(log_packet_info_ipv4(fd,logstrbuf,ip_buf,'A')){
        close(fd);
        error_msg("log packet info failed");
        exit(EXIT_FAILURE);
   }
    */
   //close(fd);

    logfile_fd = fopen(DEFAULT_LOG,"a");

    pthread_t pids[7];
    struct sock_thread_arg_t args[8];

   clock_t t;
    t = clock();

    ringbuf_init(&args[0].rbuf,(unsigned int)((LOG_BUF_SIZE_IPV4-1)*100));

    for(int i = 0; i < 8; i++){
        test_routine((void*)&args[0]);
    }
    
    t = clock() - t;
    double time_taken = ((double)t)/CLOCKS_PER_SEC;

    printf("Time taken: %f\n",time_taken);

    fclose(logfile_fd);

   return EXIT_SUCCESS; 
}
