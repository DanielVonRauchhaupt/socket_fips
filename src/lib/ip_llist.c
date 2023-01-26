#include "include/ip_llist.h"
#include <stddef.h>

struct listnode_t * create_lnode(void * key, int domain){

    struct listnode_t * lnode = callloc(sizeof(struct listnode_t),1);

    if(lnode == NULL){
        return NULL;
    }

    if(pthread_mutex_init(&lnode->lock,NULL)){
        pthread_mutex_destroy(&lnode->lock);
        free(lnode);
        return NULL;
    }

    switch (domain)
    {
    case AF_INET:
        if(lnode->key = calloc(sizeof(uint32_t),1) == NULL){
            free(lnode);
            return IP_LLIST_FAIL;
        }
    
        if(key != NULL){
            *((uint32_t *) lnode->key) = *((uint32_t *) key);
        }

        return lnode;
    
    case AF_INET6:

        if(lnode->key = calloc(sizeof(uint32_t),1) == NULL){
            free(lnode);
            return IP_LLIST_FAIL;
        }
    
        if(key != NULL){
            *((__uint128_t *) lnode->key) = *((__uint128_t * ) key);
        }

        return lnode;

    default:
        pthread_mutex_destroy(&lnode->lock);
        free(lnode);
        return IP_LLIST_FAIL;
    }
}

void destroy_lnode(struct listnode_t * lnode){
    if(lnode == NULL){
        return;
    }
    pthread_mutex_destroy(&lnode->lock);
    free(lnode->key);
    free(lnode);
}

int8_t ip_llist_init(struct ip_llist_t ** llist){

    if(*llist == NULL){
        return IP_LLIST_FAIL;
    }

    if(llist = calloc(sizeof(struct ip_llist_t),1) == NULL){
        return IP_LLIST_FAIL;
    }

    for(int i = 0; i < NBINS; i++){
        if(pthread_mutex_init(&(*llist)->bins[i].lock,NULL)){
            for(int j = i; j > -1; j--){
                pthread_mutex_destroy(&(*llist)->bins[i].lock);
            }
            free(*llist);
            return IP_LLIST_FAIL;
        }
    }    

    return IP_LLIST_SUCC;
}


int8_t ip_llist_insert(struct ip_llist_t * llist, void * key, int domain){
    if(llist == NULL || key == NULL){
        return IP_LLIST_FAIL;
    }

    struct llist_t


}


int8_t ip_llist_remove(struct ip_llist_t * llist, void * key, int domain);


int8_t ip_llist_destroy(struct ip_llist_t * llist);

