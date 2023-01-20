
#define _GNU_SOURCE
#include <linux/if_link.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <hs.h>
#include <hs/hs.h>
#include <libbpf.h>
#include <ip_blacklist.skel.h>
#include <blacklist_common.h>
#include <ini.h>
#include <net/if.h>
#include "jail.h"

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"add",		no_argument,		NULL, 'a' },
	{"del",		no_argument,		NULL, 'd' },
	{"ip",		required_argument,	NULL, 'i' },
	{"stats",	no_argument,		NULL, 's' },
	{"sec",		required_argument,	NULL, 's' },
	{"list",	no_argument,		NULL, 'l' },
	{"udp-dport",	required_argument,	NULL, 'u' },
	{"tcp-dport",	required_argument,	NULL, 't' },
	{0, 0, NULL,  0 }
};

#define FAILREGEX_UDPSVR "^([0-9]{2})-([0-9]{2})-([0-9]{4}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) client (<([^ ]+)>) exceeded request rate limit$"



struct jail_t udp_svr_jail = {.bantime=60};

static int onMatch(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void* ctx) {
    char* matched_string = (char*)ctx + from;
    size_t matched_length = to - from;
    printf("Matched string: %.*s\n", (int)matched_length, matched_string);
    return 0;
}

#define CONTENT "14-07-2023 20:48:39 client <example.com> exceeded request rate limit"

int main(int argc, char * argv[]){

    struct if_nameindex *if_ni, *i;

    if_ni = if_nameindex();
    if (if_ni == NULL) {
        perror("if_nameindex");
        return 1;
    }

    for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++) {
        printf("%u: %s\n", i->if_index, i->if_name);
    }

    if_freenameindex(if_ni);
    return 0;





    /*
	hs_database_t *database;
    hs_compile_error_t *compile_err;
    if (hs_compile(FAILREGEX_UDPSVR, HS_FLAG_DOTALL, HS_MODE_BLOCK, NULL, &database,
                   &compile_err) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to compile pattern \"%s\": %s\n",
                FAILREGEX_UDPSVR, compile_err->message);
        hs_free_compile_error(compile_err);
        return -1;
    }

	hs_scratch_t *scratch = NULL;
    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to allocate scratch space. Exiting.\n");
        hs_free_database(database);
        return -1;
    }

	if (hs_scan(database, CONTENT, sizeof(CONTENT), 0, scratch, onMatch,
                "hallo") != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting.\n");
        hs_free_scratch(scratch);
        hs_free_database(database);
        return -1;
    }



	hs_free_scratch(scratch);
	hs_free_database(database);
    */
}