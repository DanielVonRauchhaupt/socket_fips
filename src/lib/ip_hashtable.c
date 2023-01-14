#include "include/ip_hashtable.h"

int8_t ip_hashtable_init(struct ip_hashtable_t * htable,int domain){

    if(htable == NULL){
        return _IP_HASHTABLE_FAIL_;
    }

    for(uint32_t i = 0; i < NUM_BINS; i++){

        struct hashbin_t * hbin = htable->bins[i];

        if((hbin = (struct hashbin_t *) malloc(sizeof(struct hashbin_t))) == NULL){
            
            _free_hbins(htable,0,i);

            return _IP_HASHTABLE_FAIL_;
        }

        if(pthread_mutex_init(&hbin->lock,NULL)){

            _free_hbins(htable,0,i+1);

            return _IP_HASHTABLE_FAIL_;

        }

        hbin->counter = 0;

    }

    return _IP_HASHTABLE_SUCC_;

}



uint32_t ip_hashtable_inc_v4(struct ip_hashtable_t * htable, uint32_t * key){

    if(htable == NULL){
        return 0;
    }

    struct hashbin_t * hbin = htable->bins[*key & 0x0000FFFF];

    if(hbin == NULL){
        return 0;
    }

    if(pthread_mutex_lock(&hbin->lock)){
        return 0;
    }

    if(hbin->key == NULL){
        if((hbin->key = malloc(sizeof(uint32_t))) == NULL){
            pthread_mutex_unlock(&hbin->lock);
            return 0;
        }

        *((uint32_t *)hbin->key) = *key;
        
    } else if ((*(uint32_t *)hbin->key) != *key){

        struct hashbin_t * nextbin = hbin->next;

        bool match = false;

        while (nextbin != NULL)
        {
            pthread_mutex_unlock(&hbin->lock);
            if(pthread_mutex_lock(&nextbin->lock)){
                pthread_mutex_unlock(&nextbin->lock);
                return 0;
            }
            hbin = nextbin;
            nextbin = nextbin->next;

            if(*((u_int32_t *)hbin->key) == *key){
                match = true;
                break;
            }
        }

        if(!match){
            if(_init_hbin(nextbin)){
                pthread_mutex_unlock(&hbin->lock);
                return 0;
            }
            pthread_mutex_unlock(&hbin->lock);
            if(pthread_mutex_lock(&nextbin->lock)){
                pthread_mutex_unlock(&nextbin->lock);
                return 0;
            }

            hbin = nextbin;
        }
        
           
    }

    uint32_t retval = ++hbin->counter;

    pthread_mutex_unlock(&hbin->lock);

    return retval;
}


uint32_t ip_hashtable_inc_v6(struct ip_hashtable_t * htable, __uint128_t * key){

    if(htable == NULL){
        return 0;
    }

    struct hashbin_t * hbin = htable->bins[*key & 0x00000000000000000000FFFF];

    if(hbin == NULL){
        return 0;
    }

    if(pthread_mutex_lock(&hbin->lock)){
        return 0;
    }

    if(hbin->key == NULL){
        if((hbin->key = malloc(sizeof(__uint128_t))) == NULL){
            pthread_mutex_unlock(&hbin->lock);
            return 0;
        }

        *((__uint128_t *)hbin->key) = *key;
        
    } else if ((*(__uint128_t *)hbin->key) != *key){

        struct hashbin_t * nextbin = hbin->next;

        bool match = false;

        while (nextbin != NULL)
        {
            pthread_mutex_unlock(&hbin->lock);
            if(pthread_mutex_lock(&nextbin->lock)){
                pthread_mutex_unlock(&nextbin->lock);
                return 0;
            }
            hbin = nextbin;
            nextbin = nextbin->next;

            if(*((u_int32_t *)hbin->key) == *key){
                match = true;
                break;
            }
        }

        if(!match){
            if(_init_hbin(nextbin)){
                pthread_mutex_unlock(&hbin->lock);
                return 0;
            }
            pthread_mutex_unlock(&hbin->lock);
            if(pthread_mutex_lock(&nextbin->lock)){
                pthread_mutex_unlock(&nextbin->lock);
                return 0;
            }
            
            hbin = nextbin;
        }
        
           
    }

    uint32_t retval = ++hbin->counter;

    pthread_mutex_unlock(&hbin->lock);

    return retval;

}

int8_t ip_hashtable_reset(struct ip_hashtable_t * htable){

    if(htable == NULL){
        return _IP_HASHTABLE_FAIL_;
    }

    struct hashbin_t * hbin;
    int8_t status = _IP_HASHTABLE_SUCC_;

    for(uint32_t i = 0; i < NUM_BINS; i++){
        hbin = htable->bins[i];

        if(hbin != NULL){

            if(pthread_mutex_lock(&hbin->lock)){
                pthread_mutex_unlock(&hbin->lock);
                status = _IP_HASHTABLE_FAIL_;
                continue;
            }

            hbin->counter = 0;

            pthread_mutex_unlock(&hbin->lock);

            continue;

        } else {
            status = _IP_HASHTABLE_FAIL_;
        }

    }

    return status;

}

int8_t ip_hashtable_gather_stats(struct ip_hashtable_t * htable, struct ip_hashtable_stats_t * stats){

    if(htable == NULL || stats == NULL){
        return _IP_HASHTABLE_FAIL_;
    }

    stats->client_count = 0;
    stats->connection_count = 0;

    for(uint32_t i = 0; i < NUM_BINS; i++){
        struct hashbin_t * hbin, * next;

        hbin = htable->bins[i];

        while(hbin != NULL){

            if(pthread_mutex_lock(&hbin->lock)){
                pthread_mutex_unlock(&hbin->lock);
                return _IP_HASHTABLE_FAIL_;
            }

            next = hbin->next;
            if(hbin->counter > 0){stats->client_count++;}
            stats->connection_count += hbin->counter;

            pthread_mutex_unlock(&hbin->lock);

            hbin = next;

        }

    }

    return _IP_HASHTABLE_SUCC_;

}

int8_t ip_hashtable_destroy(struct ip_hashtable_t * htable){

    if(htable == NULL){
        return _IP_HASHTABLE_FAIL_;
    }

    _free_hbins(htable,0,NUM_BINS);

    return _IP_HASHTABLE_SUCC_;
}



uint8_t _init_hbin(struct hashbin_t * hbin){
    
    if((hbin = (struct hashbin_t *) malloc(sizeof(struct hashbin_t))) == NULL){
        return _IP_HASHTABLE_FAIL_;
    }

    if(pthread_mutex_init(&hbin->lock,NULL)){

        _destroy_hbin(hbin);

        return _IP_HASHTABLE_FAIL_;

    }

    hbin->counter = 0;

    return _IP_HASHTABLE_SUCC_;

}

void _free_hbins(struct ip_hashtable_t * htable,uint32_t start, uint32_t end){

    if(htable == NULL){
        return;
    }

    for(;start < end; start++){

        _destroy_hbin(htable->bins[start]);

    }

}

void _destroy_hbin(struct hashbin_t * hbin){

    if(hbin->next != NULL){
        _destroy_hbin(hbin->next);
    }
    if(hbin->key != NULL){
        free(hbin->key);
    }
    pthread_mutex_destroy(&hbin->lock);
    free(hbin);
}