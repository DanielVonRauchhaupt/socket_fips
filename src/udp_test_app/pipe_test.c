#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#define CHILD_MSG "Hello from Child"
#define PAR_MSG "Hello from Parent"

int main(void){

    int fd1[2];
    int fd2[2];

    char msg_buf[64];

    if(pipe(fd1)==-1){
        perror("Pipe 1 failed\n");
        exit(EXIT_FAILURE);
    }

    if(pipe(fd2)==-1){
        perror("Pipe 2 failed\n");
        exit(EXIT_FAILURE);
    }



    pid_t pid;

    if((pid = fork())==-1){
        perror("Fork failed\n");
        exit(EXIT_FAILURE);
    }

    if(pid == 0){

        close(fd1[0]);

        write(fd1[1],PAR_MSG,sizeof(PAR_MSG));

        close(fd1[1]);

        wait(NULL);

        read(fd2[0],msg_buf,sizeof(msg_buf));

        printf("Parent: %s\n",msg_buf);

    } else{

        close(fd2[0]);

        write(fd2[1],CHILD_MSG,sizeof(CHILD_MSG));

        close(fd2[1]);

        read(fd1[0],msg_buf,sizeof(msg_buf));

        printf("Child: %s\n",msg_buf);

        close(fd1[0]);

        exit(EXIT_SUCCESS);

    }
}
