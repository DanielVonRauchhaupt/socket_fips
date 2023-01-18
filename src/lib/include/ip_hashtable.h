#ifndef _IP_HASHTABLE_H_
#define _IP_HASHTABLE_H_
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>

#define NUM_BINS (uint32_t) 256 * 256

#define _IP_HASHTABLE_FAIL_ (int8_t) -1
#define _IP_HASHTABLE_SUCC_ (int8_t) 0

struct ip_hashtable_stats_t
{
    uint32_t client_count;
    uint64_t connection_count;
};


struct hashbin_t
{
    pthread_mutex_t lock;
    void * key;
    uint32_t counter;
    struct hashbin_t * next;
};

struct ip_hashtable_t
{
    struct hashbin_t * bins[NUM_BINS];
};

/*
    Initialises memory for the hashtable. Returns _IP_HASHTABLE_FAIL on error and _IP_HASHTABLE_SUCC on success.
*/
int8_t ip_hashtable_init(struct ip_hashtable_t * htable,int domain);

/*
    Increments or initializes the counter for "key" and returns
    the counter after incrementation. Returns 0 on error.
*/
uint32_t ip_hashtable_inc_v4(struct ip_hashtable_t * htable, uint32_t * key);

/*
    Increments or initializes the counter for "key" and returns
    the counter after incrementation. Returns 0 on error
*/
uint32_t ip_hashtable_inc_v6(struct ip_hashtable_t * htable, __uint128_t * key);

/*
    Resets all counters to 0
*/
int8_t ip_hashtable_reset(struct ip_hashtable_t * htable);

/*
    Frees memory for the hashtable. Returns -1 on error
    WARNING: Should only be called once all mutex locks are unlocked
    and no other thread is accessing the table anymore
*/
int8_t ip_hashtable_destroy(struct ip_hashtable_t * htable);


/*
    Gathers number of clients and total connections and saves them to stats
    Returns _IP_HASHTABLE_FAIL on error and _IP_HASHTABLE_SUCC on success.
*/
int8_t ip_hashtable_gather_stats(struct ip_hashtable_t * htable, struct ip_hashtable_stats_t * stats);

#endif
