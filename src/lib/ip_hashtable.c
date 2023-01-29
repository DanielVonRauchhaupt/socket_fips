#include "include/ip_hashtable.h"

#define GET_KEY_IP4(key)((*((uint32_t *)key) >> (16)) & 0xffff)
#define GET_KEY_IP6(key)(*((__uint128_t *)key))
#define HASH(key)(*((uint32_t *)key) & 0xffff)

static void destroy_hbin(struct ip_hashbin_t * hbin){

    if(hbin == NULL){
        return;
    }

    free(hbin->key);
    pthread_mutex_destroy(&hbin->lock);
    free(hbin);

}

static int init_hbin(struct ip_hashbin_t ** hbin, void * addr, int domain){

    if(hbin == NULL){
        return IP_HTABLE_NULLPTR_ERR;
    }

    bool init = false;

    if(*hbin == NULL){
        if((hbin =  calloc(sizeof(struct ip_hashbin_t),1)) == NULL){
            return IP_HTABLE_MEM_ERR;
        }
        if(pthread_mutex_init(&(*hbin)->lock,NULL) == 0){
            pthread_mutex_destroy(&(*hbin)->lock);
            free(*hbin);
            return IP_HTABLE_MEM_ERR;
        }
        bool init = true;
    }

    if(addr != NULL){
    
        switch (domain)
        {
        case AF_INET:
            if(((*hbin)->key = calloc(sizeof(uint16_t),1)) == NULL){
                if(init){
                    destroy_hbin(*hbin);
                }
                return IP_HTABLE_MEM_ERR;
            }
            
            *((uint16_t *)(*hbin)->key) = GET_KEY_IP4(addr);
            (*hbin)->count++;
            break;

        case AF_INET6:
            if(((*hbin)->key = calloc(sizeof(__uint128_t),1)) == NULL){
                if(init){
                    destroy_hbin(*hbin);
                }
                return IP_HTABLE_MEM_ERR;
            }
            *((__uint128_t *)(*hbin)->key) = GET_KEY_IP6(addr);
            (*hbin)->count++;
            break;
        
        default:
            if(init){
                destroy_hbin(*hbin);
            }
            return IP_HTABLE_ARG_ERR;
        }
    } 

    return IP_HTABLE_SUCCESS;
}

int ip_hashtable_init(struct ip_hashtable_t ** htable){

    if(htable == NULL){
        return IP_HTABLE_NULLPTR_ERR;
    }

    if((*htable = calloc(sizeof(struct ip_hashtable_t),1)) == NULL){
        return IP_HTABLE_MEM_ERR;
    }
    
    for(int i = 0; i < NBINS; i++){
        if(pthread_mutex_init(&(*htable)->hbins[i].lock,NULL)){
            ip_hashtable_destroy(*htable);
            return IP_HTABLE_MUTEX_ERR;
        }
    }

    return IP_HTABLE_SUCCESS;

}

int ip_hashtable_insert(struct ip_hashtable_t * htable, void * addr, int domain){

    if(htable == NULL || addr == NULL){
        return IP_HTABLE_NULLPTR_ERR;
    }

    struct ip_hashbin_t * hbin = &htable->hbins[HASH(addr)];
    int retval;

    if(pthread_mutex_lock(&hbin->lock)){
        pthread_mutex_unlock(&hbin->lock);
        return IP_HTABLE_MUTEX_ERR;
    }

    if(hbin->key == NULL){
        if((retval = init_hbin(&hbin,addr,domain))){
            pthread_mutex_unlock(&hbin->lock);
            return retval;
        }
        if(pthread_mutex_unlock(&hbin->lock)){
            return IP_HTABLE_MUTEX_ERR;
        }
        
        return 1;
    }

    switch (domain)
    {
    case AF_INET:
        if(*((uint16_t * )hbin->key) == GET_KEY_IP4(addr)){
            retval = ++(hbin->count);
            if(pthread_mutex_unlock(&hbin->lock)){
                return IP_HTABLE_MUTEX_ERR;
            }
            return retval;
        }
        break;

    case AF_INET6:
        if(*((__uint128_t * )hbin->key) == GET_KEY_IP6(addr)){
            retval = ++hbin->count;
            if(pthread_mutex_unlock(&hbin->lock)){
                return IP_HTABLE_MUTEX_ERR;
            }
            return retval;
        }
        break;
    
    default:
        pthread_mutex_unlock(&hbin->lock);
        return IP_HTABLE_ARG_ERR;
    }

    struct ip_hashbin_t * it = hbin->next;

    while(it != NULL){
        if(pthread_mutex_unlock(&hbin->lock)){
            return IP_HTABLE_MUTEX_ERR;
        }

        hbin = it;
        it = it->next;

        if(pthread_mutex_lock(&hbin->lock)){
            pthread_mutex_unlock(&hbin->lock);
            return IP_HTABLE_MUTEX_ERR;
        }
        if(domain == AF_INET){
            if(*((uint16_t *)hbin->key) == GET_KEY_IP4(addr)){
                retval = ++(hbin->count);
                if(pthread_mutex_unlock(&hbin->lock)){
                    return IP_HTABLE_MUTEX_ERR;
                }
                return retval;
            }
        } else if(*((__uint128_t *)hbin->key) == GET_KEY_IP6(addr)) {
            retval = ++(hbin->count);
            if(pthread_mutex_unlock(&hbin->lock)){
                return IP_HTABLE_MUTEX_ERR;
            }
            return retval;
        }
            
    }

    if((retval = init_hbin(&hbin->next,addr,domain))){
        pthread_mutex_unlock(&hbin->lock);
        return retval;
    }

    if(pthread_mutex_unlock(&hbin->lock)){
        return IP_HTABLE_MUTEX_ERR;
    }

    return 1;
}

int ip_hashtable_remove(struct ip_hashtable_t * htable, void * addr, int domain){

    if(htable == NULL || addr == NULL){
        return IP_HTABLE_NULLPTR_ERR;
    }

    struct ip_hashbin_t * hbin = &htable->hbins[HASH(addr)];
    int retval;
    bool match;

    if(pthread_mutex_lock(&hbin->lock)){
        pthread_mutex_unlock(&hbin->lock);
        return IP_HTABLE_MUTEX_ERR;
    }

    if(hbin->key == NULL){
        if(pthread_mutex_unlock(&hbin->lock)){
            
            return IP_HTABLE_MUTEX_ERR;
        }

        return 0;
    }

    switch (domain)
    {
        case AF_INET:

            if(*((uint16_t *)hbin->key) == GET_KEY_IP4(addr)){
                retval = hbin->count;
                match = true;
            }
            break;

        case AF_INET6:

            if(*((__uint128_t *)hbin->key) == GET_KEY_IP6(addr)){
                retval = hbin->count;
                match = true;
            }
            break;
    
    default:
        pthread_mutex_unlock(&hbin->lock);
        return IP_HTABLE_ARG_ERR;
    }

    if(match){

        free(hbin->key);

        if(hbin->next != NULL){
            struct ip_hashbin_t * temp = hbin->next;

            if(pthread_mutex_lock(&temp->lock)){
                pthread_mutex_unlock(&temp->lock);
                pthread_mutex_unlock(&hbin->lock);
                return IP_HTABLE_MUTEX_ERR;
            }

            hbin->count = temp->count;
            hbin->key = temp->key;
            hbin->next = temp->next;

            if(pthread_mutex_unlock(&hbin->lock)){
                destroy_hbin(temp);
                return IP_HTABLE_MUTEX_ERR;
            }

            destroy_hbin(temp);

            return retval;

        }
    
    }

    struct ip_hashbin_t * it = hbin->next;

    while(it != NULL){

        if(pthread_mutex_lock(&it->lock)){
            pthread_mutex_unlock(&hbin->lock);
            pthread_mutex_unlock(&hbin->lock);
            return IP_HTABLE_MUTEX_ERR;
        }

        if(domain == AF_INET){
            if(*((uint16_t *)hbin->key) == GET_KEY_IP4(addr)){
                retval = hbin->count;
                match = true;
            }
        }

        else if(*((__uint128_t *)hbin->key) == GET_KEY_IP6(addr)){
            retval = hbin->count;
            match = true;
        }

        if(match){

            hbin->next = it->next;

            if(pthread_mutex_unlock(&hbin->lock)){
                destroy_hbin(it);
                return IP_HTABLE_MUTEX_ERR;
            }

            destroy_hbin(it);

            return retval;

        }

    }

    if(pthread_mutex_unlock(&hbin->lock)){
        return IP_HTABLE_MUTEX_ERR;
    }

    return 0;    

}

int ip_hashtable_destroy(struct ip_hashtable_t * htable){

    if(htable == NULL){
        return IP_HTABLE_NULLPTR_ERR;
    }

    int addr_count = 0, error = 0; 

    for(int i = 0; i < NBINS; i++){

        struct ip_hashbin_t *prev, *it = htable->hbins[i].next;

        if(pthread_mutex_destroy(&it->lock)){
            error = IP_HTABLE_MUTEX_ERR;
        }

        if(it->key != NULL){
            free(it->key);
            addr_count++;
        }

        while(it != NULL){
            prev = it;
            it = it->next;
            destroy_hbin(prev);
            addr_count++;
        }

    }

    free(htable);

    if(error){
        return error;
    }

    return addr_count;

}


