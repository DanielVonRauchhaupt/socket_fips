#ifndef IP_LLIST_H
#define IP_LLIST_H
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>

#define IP_LLIST_FAIL (-1)
#define IP_LLIST_SUCC (0)

#define NBINS 256


struct listnode_t
{
    pthread_mutex_t lock;
    void * key;
    time_t timestamp;
    struct listnode_t * next;
};

struct ip_llist_t
{
    struct listnode_t bins[NBINS];
};

/*
    Initialises memory for the llist. Returns _IP_llist_FAIL on error and _IP_llist_SUCC on success.
*/
int8_t ip_llist_init(struct ip_llist_t ** htable);

/*
    Increments or initializes the counter for "key" and returns
    the counter after incrementation. Returns 0 on error.
*/
int8_t ip_llist_insert(struct ip_llist_t * htable, void * key, int domain);

/*
    Increments or initializes the counter for "key" and returns
    the counter after incrementation. Returns 0 on error
*/
int8_t ip_llist_remove(struct ip_llist_t * htable, void * key, int domain);

/*
    Frees memory for the llist. Returns -1 on error
    WARNING: Should only be called once all mutex locks are unlocked
    and no other thread is accessing the table anymore
*/
int8_t ip_llist_destroy(struct ip_llist_t * htable);


/*
    Gathers number of clients and total connections and saves them to stats
    Returns _IP_llist_FAIL on error and _IP_llist_SUCC on success.
*/

#endif