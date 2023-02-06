#include "include/ip_llist.h"
#include <stddef.h>

static int create_lnode(struct ip_listnode_t ** lnode,void * key, time_t * ts, int domain){

    if(lnode == NULL || key == NULL || ts == NULL){
        return IP_LLIST_NULLPTR_ERR;
    }

    if((*lnode = (struct ip_listnode_t * ) calloc(sizeof(struct ip_listnode_t),1)) == NULL){
            return IP_LLIST_MEM_ERR;
    }

    (*lnode)->timestamp = *ts;

    switch (domain)
    {
    case AF_INET:
        if(((*lnode)->key = calloc(sizeof(uint32_t),1)) == NULL){
            free(lnode);
            return IP_LLIST_MEM_ERR;
        }
        *((uint32_t *)(*lnode)->key) = *((uint32_t *) key);
        (*lnode)->domain = AF_INET;

        return IP_LLIST_SUCCESS;
    
    case AF_INET6:

        if(((*lnode)->key = calloc(sizeof(__uint128_t),1)) == NULL){
            free(lnode);
            return IP_LLIST_MEM_ERR;
        }
        *((__uint128_t *)(*lnode)->key) = *((__uint128_t * ) key);
        (*lnode)->domain = AF_INET6;

        return IP_LLIST_SUCCESS;

    default:
        free(lnode);
        return IP_LLIST_ARG_ERR;
    }
}

static void destroy_lnode(struct ip_listnode_t ** lnode){

    if(*lnode == NULL){
        return;
    }
    
    free((*lnode)->key);
    free(*lnode);
    *lnode = NULL;
    
}

int ip_llist_init(struct ip_llist_t ** llist){

    if(llist == NULL){
        return IP_LLIST_NULLPTR_ERR;
    }

    if((*llist = calloc(sizeof(struct ip_llist_t),1)) == NULL){
        return IP_LLIST_MEM_ERR;
    }

    if(pthread_mutex_init(&(*llist)->tail_lock,NULL)){
        pthread_mutex_destroy(&(*llist)->tail_lock);
        return IP_LLIST_MUTEX_ERR;
    }

    return IP_LLIST_SUCCESS;
}


int ip_llist_append(struct ip_llist_t * llist, void * key, time_t * ts, int domain){

    if(llist == NULL || key == NULL){
        return IP_LLIST_NULLPTR_ERR;
    }

    int retval;    
    struct ip_listnode_t * new;

    if((retval = create_lnode(&new,key,ts,domain))){
        return retval;
    }

    if(pthread_mutex_lock(&llist->tail_lock)){
        pthread_mutex_unlock(&llist->tail_lock);
        return IP_LLIST_MUTEX_ERR;
    }

    if(llist->tail == NULL){
        llist->head = new;
        llist->tail = new;
    } 

    else{
        llist->tail->next = new;
        llist->tail = new;
    }

    if(pthread_mutex_unlock(&llist->tail_lock)){
        return IP_LLIST_MUTEX_ERR;
    }

    return IP_LLIST_SUCCESS;
}


int ip_llist_remove(struct ip_listnode_t ** node, struct ip_listnode_t * prev){

    if(node == NULL || *node == NULL){
        return IP_LLIST_NULLPTR_ERR;
    }

    if(prev != NULL){
        prev->next = (*node)->next;
    }

    destroy_lnode(node);

    return IP_LLIST_SUCCESS;

}


int ip_llist_destroy(struct ip_llist_t ** llist){

    if(llist == NULL || *llist){
        return IP_LLIST_NULLPTR_ERR;
    }

    int error,retval = IP_LLIST_SUCCESS;
    struct ip_listnode_t * prev, * it = (*llist)->head;

    while (it != NULL)
    {
        prev = it;
        it = it->next;
        if((retval = ip_llist_remove(prev,NULL)) < 0){
            error = retval;
        }
    }

    if(pthread_mutex_destroy(&(*llist)->tail_lock)){
        error = IP_LLIST_MUTEX_ERR;
    }

    free(*llist);

    *llist = NULL;
    
    if(error){
        return error;
    }

    return IP_LLIST_SUCCESS;
}

