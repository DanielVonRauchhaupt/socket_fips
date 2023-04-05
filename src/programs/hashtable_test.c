#include <ip_hashtable.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>


void * del_routine(void * arg)
{
    __uint128_t start = 0;

    struct ip_hashtable_t * htable = (struct ip_hashtable_t *) arg;

    for(int i = 0; i < 65000; i++)
    {
        ip_hashtable_remove(htable, &start, AF_INET6);
        start++;
    }

    return NULL;
}

void * add_routine(void * arg)
{
    __uint128_t start = 0;

    struct ip_hashtable_t * htable = (struct ip_hashtable_t *) arg;

    for(int i = 0; i < 65000; i++)
    {
        ip_hashtable_insert(htable, &start, AF_INET6);
        start++;
    }

    return NULL;
}

static inline uint16_t jenkins_hash_ipv6(__uint128_t * key) 
{

    uint8_t *key_bytes = (uint8_t *)key;
    uint64_t hash_value = 0;
    for (int i = 0; i < 16; i++) 
    {
        hash_value += key_bytes[i];
        hash_value += (hash_value << 10);
        hash_value ^= (hash_value >> 6);
    }
    hash_value += (hash_value << 3);
    hash_value ^= (hash_value >> 11);
    hash_value += (hash_value << 15);
    return (uint16_t) hash_value % NBINS;
}

int main(void)
{

    struct ip_hashtable_t * htable;
    __uint128_t start = 0;
    pthread_t pid1, pid2;

    ip_hashtable_init(&htable);

    pthread_create(&pid1, NULL, add_routine, htable);

    pthread_create(&pid2, NULL, del_routine, htable);

    for(int i = 0; i < 65000; i++)
    {

        ip_hashtable_insert(htable, &start, AF_INET6);

        start++;

    }

    pthread_join(pid1, NULL);

    pthread_join(pid2, NULL);

    printf("count = %d\n", ip_hashtable_destroy(&htable));

}