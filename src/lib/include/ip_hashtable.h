#ifndef _IP_HASHTABLE
#define _IP_HASHTABLE

#include <arpa/inet.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
/**
 *  Small and simple hashtable to store IPv4 and IPv6 Addresses
 * 
 *  All functions beside init and destroy are MT-safe
 * 
 *  The Hashfuntion is simply using the lower 2 bytes of an address as an index
*/

// Number of binds used by the hashtable
#define NBINS 256 * 256

#define IP_HTABLE_SUCCESS (0) // Success return code
#define IP_HTABLE_ARG_ERR (-1) // Error type for invalid argument errors
#define IP_HTABLE_NULLPTR_ERR (-2) // Error type for nullpointer error
#define IP_HTABLE_MEM_ERR (-3) // Error type for memory allocation failures 
#define IP_HTABLE_MUTEX_ERR (-4) // Error type for mutex failures

// Struct to store a single hashtable entry
struct ip_hashbin_t
{ 
   void * key;
   int domain;
   uint32_t count;
   pthread_mutex_t lock;
   struct ip_hashbin_t * next;

};

// Struct to store the entire hashtable
struct ip_hashtable_t {

    struct ip_hashbin_t hbins[NBINS];
};

/*
    Initialises memory for the ip_hashtable_t struct (Should be called before entering multi-threaded context)
*/
int ip_hashtable_init(struct ip_hashtable_t ** htable);

/*
    Inserts an ip address into the hashtable and returns its count on succcess (> 1 for already present addresses) 
*/
int ip_hashtable_insert(struct ip_hashtable_t * htable, void * key, int domain);

/*
    Removes the value addr from the table. Returns the count on success or zero if the address is not present
*/
int ip_hashtable_remove(struct ip_hashtable_t * htable, void * key, int domain);

/*
    Frees memory for the ip_hasttable_t struct (Should be called after exiting the multi threaded context)
*/
int ip_hashtable_destroy(struct ip_hashtable_t ** htable); 


#endif