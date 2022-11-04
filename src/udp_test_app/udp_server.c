#include <stdio.h> 
#include <stdlib.h> 
#include <time.h>
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

    
#define DEFAULT_PORT 8080 
#define DEFAULT_LOG "log.txt"
#define DATE_TIME_SIZE 20


void log_message(const char * msg){

    FILE * logfile;

    logfile = fopen(DEFAULT_LOG,"a");

    fputs(msg,logfile);

    fclose(logfile);

}

void log_packet_info(const char* addr,unsigned int port,char payload){

    FILE * logfile;
    time_t t;
    char timebuf[DATE_TIME_SIZE];
    t = time(NULL);
    strftime(timebuf, DATE_TIME_SIZE, "%Y-%m-%d %H:%M:%S", localtime(&t));
    logfile = fopen(DEFAULT_LOG,"a");
    fprintf(logfile,"Packet Reveived : Datetime = %s, Address = %s, Port = %u, Payload = %u\n", timebuf,addr,port,(uint8_t)payload);
    fclose(logfile);

}

    
int main(int argc, char ** argv) { 
    int sockfd; 
    char buffer; 
    struct sockaddr_in servaddr, cliaddr;      

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { 
        perror("Could not open socket"); 
        exit(EXIT_FAILURE); 
    } 
        
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
        
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = (argc > 1) ? htons((int)strtol(argv[1],NULL,10)) :  htons(DEFAULT_PORT); 
        
    if ( bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 ) 
    { 
        fprintf(stderr,"Failed to bind at port %d\n", servaddr.sin_port);
        servaddr.sin_port = htons(DEFAULT_PORT);
        if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
            perror("Could not bind socket"); 
            exit(EXIT_FAILURE); 
        }
        
    }

    
        
    __socklen_t len; 
    
    len = sizeof(cliaddr);

    while(1){
        recvfrom(sockfd, &buffer, 1,  MSG_WAITALL, ( struct sockaddr *) &cliaddr, &len);      
        log_packet_info(inet_ntoa(cliaddr.sin_addr),(unsigned int) ntohs(cliaddr.sin_port),(unsigned int)buffer);
        buffer += 1;
        sendto(sockfd, &buffer, 1, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len); 
    }  
        
    return 0; 
}
