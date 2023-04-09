#ifndef _IP_TO_STR_H
#define _IP_TO_STR_H
#include <stdint.h>

uint8_t ipv4_to_str(uint32_t * src, char * dst);

uint8_t ipv6_to_str(__uint128_t * src, char * dst);

uint8_t ipv6_to_str_fancy(__uint128_t * src, char * dst);

#endif
