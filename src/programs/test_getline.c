#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void * thread_routine(void * arg){

    char * buf;
    size_t len;

    FILE * file = (FILE *)arg;
    ssize_t sz = 0;
    pthread_t id = pthread_self();

    while(1){

        buf = NULL;
        len = 0;

        sz = getline(&buf,&len,file);

        if(sz < 0){
            break;
        }

        //pthread_mutex_lock(&lock);
        //printf("Thread %ld : %s",id, buf);
        //pthread_mutex_unlock(&lock);

        free(buf);

    }

    return NULL;
}


int main(void){

    pthread_t thread1;
    pthread_t thread2;

    FILE * file = fopen("output.txt","r");

    if(file == NULL){
        exit(EXIT_FAILURE);
    }

    //pthread_create(&thread1,NULL,thread_routine,(void*)file);
    //pthread_create(&thread2,NULL,thread_routine,(void*)file);

    thread_routine((void *)file);

    //pthread_join(thread1,NULL);
    //pthread_join(thread2,NULL);


}