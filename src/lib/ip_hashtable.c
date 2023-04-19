#include "include/ip_hashtable.h"

#define GET_KEY_IP4(key)(*((uint32_t *)key))
#define GET_KEY_IP6(key)(*((__uint128_t *)key))

static inline uint32_t spooky_hash(void * src, uint8_t len)
{
   return spooky_hash32(src, len, 0) % NBINS;
}

static int destroy_hbin(struct ip_hashbin_t ** hbin)
{

    int retval;

    if(hbin == NULL)
    {
        return IP_HTABLE_NULLPTR_ERR;
    }
    
    free((*hbin)->key);
    retval = pthread_mutex_destroy(&(*hbin)->lock);
    free(*hbin);
    *hbin = NULL;

    return (retval) ? IP_HTABLE_MEM_ERR : IP_HTABLE_SUCCESS;
}

static int init_hbin(struct ip_hashbin_t ** hbin, void * addr, int domain)
{

    if(hbin == NULL)
    {
        return IP_HTABLE_NULLPTR_ERR;
    }

    bool init = false;

    if(*hbin == NULL)
    {
        if((*hbin = calloc(sizeof(struct ip_hashbin_t), 1)) == NULL)
        {
            return IP_HTABLE_MEM_ERR;
        }
        bool init = true;
    }

    if(addr != NULL)
    {
    
        switch (domain)
        {
        case AF_INET:
            if(((*hbin)->key = calloc(sizeof(uint32_t), 1)) == NULL)
            {
                if(init)
                {
                    destroy_hbin(hbin);
                }
                return IP_HTABLE_MEM_ERR;
            }
            (*hbin)->domain = AF_INET;
            GET_KEY_IP4((*hbin)->key) = GET_KEY_IP4(addr);
            (*hbin)->count = 1;
            break;

        case AF_INET6:
            if(((*hbin)->key = calloc(sizeof(__uint128_t), 1)) == NULL)
            {
                if(init)
                {
                    destroy_hbin(hbin);
                }
                return IP_HTABLE_MEM_ERR;
            }

            (*hbin)->domain = AF_INET6;
            GET_KEY_IP6((*hbin)->key) = GET_KEY_IP6(addr);
            (*hbin)->count = 1;
            break;
            
        
        default:
            if(init)
            {
                destroy_hbin(hbin);
            }
            return IP_HTABLE_ARG_ERR;
        }
    } 

    return IP_HTABLE_SUCCESS;
}

int ip_hashtable_init(struct ip_hashtable_t ** htable)
{

    if(htable == NULL)
    {
        return IP_HTABLE_NULLPTR_ERR;
    }

    if((*htable = calloc(sizeof(struct ip_hashtable_t),1)) == NULL)
    {
        return IP_HTABLE_MEM_ERR;
    }

    return IP_HTABLE_SUCCESS;

}

int ip_hashtable_insert(struct ip_hashtable_t * htable, void * addr, int domain)
{

    if(htable == NULL || addr == NULL)
    {
        return IP_HTABLE_NULLPTR_ERR;
    }

    // Retreive container assigned by hashfunction
    int retval;
    uint32_t index = (domain == AF_INET) ? spooky_hash(addr, 4) : spooky_hash(addr, 16);
    struct ip_hashbin_t * hbin = &htable->hbins[index];

    // Claim lock of container
    if(pthread_mutex_lock(&hbin->lock))
    {
        return IP_HTABLE_MUTEX_ERR;
    }

    // Initialize container if empty
    if(hbin->key == NULL)
    {

        if((retval = init_hbin(&hbin , addr, domain)))
        {
            pthread_mutex_unlock(&hbin->lock);
            return retval;
        }
        if(pthread_mutex_unlock(&hbin->lock))
        {
            return IP_HTABLE_MUTEX_ERR;
        }
        return 1;
    }

    // Check if container entry matches address
    switch (domain)
    {
    case AF_INET:
        if(hbin->domain == domain)
        {
            if(GET_KEY_IP4(hbin->key) == GET_KEY_IP4(addr))
            {
                retval = ++(hbin->count);
                if(pthread_mutex_unlock(&hbin->lock))
                {
                    return IP_HTABLE_MUTEX_ERR;
                }
                return retval;
            }
        }
        break;

    case AF_INET6:
        if(hbin->domain == domain)
        {
            if(GET_KEY_IP6(hbin->key) == GET_KEY_IP6(addr))
            {
                retval = ++hbin->count;
                if(pthread_mutex_unlock(&hbin->lock))
                {
                    return IP_HTABLE_MUTEX_ERR;
                }
                return retval;
            }
        }
        break;
        
    default:
        pthread_mutex_unlock(&hbin->lock);
        return IP_HTABLE_ARG_ERR;
    }

    // Iterate through linked list of containers, until match or end of list
    struct ip_hashbin_t * it = hbin->next;

    while(it != NULL)
    {

        if(pthread_mutex_lock(&it->lock))
        {
            pthread_mutex_unlock(&hbin->lock);
            return IP_HTABLE_MUTEX_ERR;
        }

        if(pthread_mutex_unlock(&hbin->lock))
        {
            pthread_mutex_lock(&it->lock);
            return IP_HTABLE_MUTEX_ERR;
        }

        hbin = it;
        it = it->next;

        if(domain == AF_INET && hbin->domain == AF_INET)
        {
            if(GET_KEY_IP4(hbin->key) == GET_KEY_IP4(addr))
            {
                retval = ++(hbin->count);
                if(pthread_mutex_unlock(&hbin->lock))
                {
                    return IP_HTABLE_MUTEX_ERR;
                }
                return retval;
            }
        } 

        else if(domain == AF_INET6 && hbin->domain == AF_INET6)
        {
            if(GET_KEY_IP6(hbin->key) == GET_KEY_IP6(addr)) 
            {
                retval = ++(hbin->count);
                if(pthread_mutex_unlock(&hbin->lock))
                {
                    return IP_HTABLE_MUTEX_ERR;
                }
                return retval;
            }
        }
        
            
    }

    if((retval = init_hbin(&hbin->next,addr,domain)))
    {
        pthread_mutex_unlock(&hbin->lock);
        return retval;
    }

    if(pthread_mutex_unlock(&hbin->lock))
    {
        return IP_HTABLE_MUTEX_ERR;
    }

    return 1;
}

int ip_hashtable_remove(struct ip_hashtable_t * htable, void * addr, int domain)
{

    if(htable == NULL || addr == NULL)
    {
        return IP_HTABLE_NULLPTR_ERR;
    }

    int retval;
    uint32_t index = (domain == AF_INET) ? spooky_hash(addr, 4) : spooky_hash(addr, 16);;
    struct ip_hashbin_t * hbin = &htable->hbins[index];
    bool match;

    if(pthread_mutex_lock(&hbin->lock))
    {
        return IP_HTABLE_MUTEX_ERR;
    }

    if(hbin->key == NULL)
    {
        if(pthread_mutex_unlock(&hbin->lock))
        {
            
            return IP_HTABLE_MUTEX_ERR;
        }

        return IP_HTABLE_NOEXIST;
    }

    switch (domain)
    {
        case AF_INET:
            if(hbin->domain == AF_INET)
            {
                if(GET_KEY_IP4(hbin->key) == GET_KEY_IP4(addr))
                {
                    retval = hbin->count;
                    match = true;
                }
            }
            break;

        case AF_INET6:
            if(hbin->domain == AF_INET6)
            {
                if(GET_KEY_IP6(hbin->key) == GET_KEY_IP6(addr))
                {
                    retval = hbin->count;
                    match = true;
                }
            }
            break;
    
    default:
        pthread_mutex_unlock(&hbin->lock);
        return IP_HTABLE_ARG_ERR;
    }

    if(match)
    {

        if(hbin->next != NULL)
        {
            struct ip_hashbin_t * temp = hbin->next;

            if(pthread_mutex_lock(&temp->lock))
            {
                pthread_mutex_unlock(&hbin->lock);
                return IP_HTABLE_MUTEX_ERR;
            }

            hbin->count = temp->count;
            hbin->next = temp->next;
            hbin->domain = temp->domain;

            if(temp->domain == AF_INET)
            {
                GET_KEY_IP4(hbin->key) = GET_KEY_IP4(temp->key);
            }
            else
            {
                GET_KEY_IP6(hbin->key) = GET_KEY_IP6(temp->key);
            }

            if(pthread_mutex_unlock(&hbin->lock))
            {
                destroy_hbin(&temp);
                return IP_HTABLE_MUTEX_ERR;
            }

            destroy_hbin(&temp);

            return retval;

        }

        else 
        {
            free(hbin->key);
            hbin->key = NULL;
        }

        retval = hbin->count;
        hbin->count = 0;

        if(pthread_mutex_unlock(&hbin->lock))
        {
            return IP_HTABLE_MUTEX_ERR;
        }
    
        return retval; 
    }

    struct ip_hashbin_t * it = hbin;

    while(it->next != NULL)
    {

        it = it->next;

        if(pthread_mutex_lock(&it->lock))
        {
            pthread_mutex_unlock(&hbin->lock);
            return IP_HTABLE_MUTEX_ERR;
        }

        if(domain == AF_INET && it->domain == AF_INET)
        {
            if(GET_KEY_IP4(it->key) == GET_KEY_IP4(addr))
            {
                retval = it->count;
                match = true;
            }
        }

        else if(it->domain == AF_INET6 && domain == AF_INET6)
        {

            if(GET_KEY_IP6(it->key) == GET_KEY_IP6(addr))
            {
                retval = it->count;
                match = true;
            }

        }

        if(match)
        {

            hbin->next = it->next;

            if(pthread_mutex_unlock(&hbin->lock))
            {
                destroy_hbin(&it);
                return IP_HTABLE_MUTEX_ERR;
            }

            destroy_hbin(&it);

            return retval;

        }

        if(pthread_mutex_unlock(&hbin->lock))
        {
            pthread_mutex_unlock(&it->lock);
            return IP_HTABLE_MUTEX_ERR;
        }

        hbin = it;

    }

    if(pthread_mutex_unlock(&hbin->lock))
    {
        return IP_HTABLE_MUTEX_ERR;
    }

    return IP_HTABLE_NOEXIST;    

}

int ip_hashtable_set(struct ip_hashtable_t * htable, void * addr, int domain, uint32_t value)
{

    if(htable == NULL || addr == NULL)
    {
        return IP_HTABLE_NULLPTR_ERR;
    }

    int retval;
    uint32_t index = (domain == AF_INET) ? spooky_hash(addr, 4) : spooky_hash(addr, 16);
    struct ip_hashbin_t * hbin = &htable->hbins[index];
    bool match;

    if(pthread_mutex_lock(&hbin->lock))
    {
        return IP_HTABLE_MUTEX_ERR;
    }

    if(hbin->key == NULL)
    {
        if(pthread_mutex_unlock(&hbin->lock))
        {
            
            return IP_HTABLE_MUTEX_ERR;
        }

        return IP_HTABLE_NOEXIST;
    }

    switch (domain)
    {
        case AF_INET:
            if(hbin->domain == AF_INET)
            {
                if(GET_KEY_IP4(hbin->key) == GET_KEY_IP4(addr))
                {
                    retval = hbin->count;
                    hbin->count = value;

                    if(pthread_mutex_unlock(&hbin->lock))
                    {
                        return IP_HTABLE_MUTEX_ERR;
                    }

                    return retval;
                }
            }
            break;

        case AF_INET6:
            if(hbin->domain == AF_INET6)
            {
                if(GET_KEY_IP6(hbin->key) == GET_KEY_IP6(addr))
                {
                    retval = hbin->count;
                    hbin->count = value;

                    if(pthread_mutex_unlock(&hbin->lock))
                    {
                        return IP_HTABLE_MUTEX_ERR;
                    }

                    return retval;
                }
            }
            break;
    
    default:
        pthread_mutex_unlock(&hbin->lock);
        return IP_HTABLE_ARG_ERR;
    }

    struct ip_hashbin_t * it = hbin;

    while(it->next != NULL)
    {

        it = it->next;

        if(pthread_mutex_lock(&it->lock))
        {
            pthread_mutex_unlock(&hbin->lock);
            return IP_HTABLE_MUTEX_ERR;
        }

        if(pthread_mutex_unlock(&hbin->lock))
        {
            pthread_mutex_unlock(&it->lock);
            return IP_HTABLE_MUTEX_ERR;
        }

        if(domain == AF_INET && it->domain == AF_INET)
        {
            if(GET_KEY_IP4(it->key) == GET_KEY_IP4(addr))
            {
                retval = it->count;
                it->count = value;

                if(pthread_mutex_unlock(&it->lock))
                {
                    return IP_HTABLE_MUTEX_ERR;
                }

                return retval;    
            }
        }

        else if(it->domain == AF_INET6 && domain == AF_INET6)
        {

            if(GET_KEY_IP6(it->key) == GET_KEY_IP6(addr))
            {
                retval = it->count;
                it->count = value;

                if(pthread_mutex_unlock(&it->lock))
                {
                    return IP_HTABLE_MUTEX_ERR;
                }

                return retval;
            }

        }

        hbin = it;

    }

    if(pthread_mutex_unlock(&hbin->lock))
    {
        return IP_HTABLE_MUTEX_ERR;
    }

    return IP_HTABLE_NOEXIST;    

}

int ip_hashtable_destroy(struct ip_hashtable_t ** htable)
{

    if(htable == NULL || *htable == NULL)
    {
        return IP_HTABLE_NULLPTR_ERR;
    }

    int addr_count = 0, error = 0, retval; 

    for(int i = 0; i < NBINS; i++)
    {

        struct ip_hashbin_t *prev = NULL, *it = &(*htable)->hbins[i];

        if(it->key != NULL)
        {
            free(it->key);
            addr_count++;
        }

        it = it->next;

        while(it != NULL)
        {
            prev = it;
            it = it->next;
            if((retval = destroy_hbin(&prev)))
            {
                error = retval;
            }
            addr_count++;
        }

    }

    free(*htable);
    *htable = NULL;

    if(error)
    {
        return error;
    }

    return addr_count;

}


