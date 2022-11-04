#include <stdlib.h>
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>


#define ID 17
#define MSG_PAR "Hello from Parent"
#define MSG_CHILD "Hello from Child"
#define OFFSET 50
#define SIZE 100

int main(void){

    pid_t pid;

    if((pid = fork())==-1){
        perror("Fork failed\n");
        exit(EXIT_FAILURE);
    }

    key_t key = ftok("shmfile",ID);

    int shmid = shmget(key,SIZE,0666|IPC_CREAT);

    char *str = (char*) shmat(shmid,(void*)0,0);

    if(pid == 0){

        memcpy(str+OFFSET,MSG_PAR,sizeof(MSG_PAR));

        wait(NULL);

        printf("Message: %s\n",str);

        shmdt(str);

        shmctl(shmid,IPC_RMID,NULL);

        exit(EXIT_SUCCESS);

    } else{

        memcpy(str,MSG_CHILD,sizeof(MSG_CHILD));

        printf("Message: %s\n",str+OFFSET);

        shmdt(str);

        exit(EXIT_SUCCESS);

    }

}
