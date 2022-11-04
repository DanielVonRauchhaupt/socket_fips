#include <stdio.h> 
#include <stdlib.h> 
#include <time.h>
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#define PORT 8080
#define MESSAGE_SIZE 17
#define MESSAGE "Hello from Child"

int main(void){

    int sockfd;
    pid_t pid;
    socklen_t len;
    char msg_buf[MESSAGE_SIZE];
    struct sockaddr_in servaddr, clientaddr;

    memset(msg_buf,0,MESSAGE_SIZE);

    if((pid = fork())== -1){
        perror("Fork failed\n");
        exit(EXIT_FAILURE);
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) { 
        perror("Socket creation failed\n"); 
        exit(EXIT_FAILURE); 
    }     
    
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&clientaddr, 0, sizeof(clientaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    servaddr.sin_addr.s_addr = INADDR_ANY;
    
    if(pid == 0){

        if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
            perror("Could not bind socket"); 
            exit(EXIT_FAILURE); 
        }

        recvfrom(sockfd,(void*) &msg_buf, MESSAGE_SIZE,  MSG_WAITALL, (struct sockaddr *) &clientaddr, &len);  

        msg_buf[sizeof(msg_buf)-1] = '\0';

        printf("Message : %s\n",msg_buf);



    } else {

        sendto(sockfd,(void*) MESSAGE, sizeof(MESSAGE), MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));

    }

    exit(EXIT_SUCCESS);
}