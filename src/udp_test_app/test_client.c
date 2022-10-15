#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
    
#define DEFAULT_PORT 8080 
#define NUMBER 10
    
int main(int argc, char ** argv) { 
    int sockfd; 
    char buffer; 
    char message = (argc > 2) ? (char)(strtol(argv[2],NULL,10)) : 10;
    struct sockaddr_in servaddr; 
    
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
    
    memset(&servaddr, 0, sizeof(servaddr)); 
        
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = (argc > 1) ? htons((int) strtol(argv[1],NULL,10)) : htons(DEFAULT_PORT); 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
        
    socklen_t len; 
        
    sendto(sockfd,(void*) &message, 1, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr)); 

    printf("Client : Sent Payload : %d\n",(int) message);
            
    recvfrom(sockfd,(void*) &buffer, 1,  MSG_WAITALL, (struct sockaddr *) &servaddr, &len);  

    printf("Client : Received Payload : %d\n",(int) buffer); 
    
    close(sockfd); 
    return 0; 
}