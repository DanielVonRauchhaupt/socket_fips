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


void log_message(const char * msg){

    FILE * logfile;

    logfile = fopen(DEFAULT_LOG,"a");

    fputs(msg,logfile);

    fclose(logfile);

}
    
int main() { 
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
    servaddr.sin_port = htons(DEFAULT_PORT); 
        
    if ( bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 ) 
    { 
        perror("Could not bind socket"); 
        exit(EXIT_FAILURE); 
    } 
        
    __socklen_t len; 
    time_t t;

    char buf[21];
    char logstring[128];

    memset(logstring,0,sizeof(logstring));
    
    len = sizeof(cliaddr);

    while(1){
        recvfrom(sockfd, &buffer, 1,  MSG_WAITALL, ( struct sockaddr *) &cliaddr, &len);
        t = time(NULL);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
        printf("Server : Number Received : %d\n",(int)buffer); 
        printf("Address : %s\n",inet_ntoa(cliaddr.sin_addr));
        printf("Port : %d\n", (int) ntohs(cliaddr.sin_port));
        printf("Time : %s\n", buf);
        log_message("Hello");
        buffer += 1;
        sendto(sockfd, &buffer, 1, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len); 
    }  
        
    return 0; 
}