#include <hs/hs.h>
#include <time.h>
#include "ipc.h"
#include <list.h>
#include <stdatomic.h>
#include <pthread.h>

#define HOST_RE "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3} \
(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[0-9a-fA-F]{1,4}:){7} \
[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6} \
:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?: \
[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3} \
(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5} \
|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:) \
|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1} \
(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]) \
{0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"

#define BANTIME_DEFAULT (uint32_t)(60)
#define MAX_ARG_LEN 256

#define BUFSIZE 256 * 256


struct client_t {
    const char * ip_address;
    time_t timestamp;
};

struct jail_t
{
    const char * name;
    union ipc_parameters_t * ips_pars;
    const char * fail_regex;
    uint32_t bantime;
    hs_database_t * hs_database;
    hs_scratch_t * scratch;

};
