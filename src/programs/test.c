#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>

#define ADDR1 "2001:0db8:c0a8:0101:0000:0000:0000:0002"

#define NBINS 256 * 256

static inline uint16_t jenkins_hash_ipv6(struct in6_addr * key) 
{
    uint8_t *key_bytes = (uint8_t *)key;
    __uint128_t hash_value = 0;
    for (int i = 0; i < 16; i++) 
    {
        hash_value += key_bytes[i];
        hash_value += (hash_value << 10);
        hash_value ^= (hash_value >> 6);
    }
    hash_value += (hash_value << 3);
    hash_value ^= (hash_value >> 11);
    hash_value += (hash_value << 15);
    return hash_value % NBINS;
}

int main(void)
{

    struct in6_addr addr;

    inet_pton(AF_INET6, ADDR1, &addr);

    printf("addr %lld\n",*(&addr));

    printf("hash : %u\n", jenkins_hash_ipv6(&addr));

}