#ifndef __XDP_DDOS01_BLACKLIST_COMMON_H
#define __XDP_DDOS01_BLACKLIST_COMMON_H
//#define DEBUG 1
//#define LONGTERM 1
//#define SUBNET
#define SUBNET_THRESHOLD 3

#include <time.h>
#include <bpf/libbpf.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>

/* Exit return codes */
#define	EXIT_OK			0
#define EXIT_FAIL		1
#define EXIT_FAIL_OPTION	2
#define EXIT_FAIL_XDP		3
#define EXIT_FAIL_MAP		20
#define EXIT_FAIL_MAP_KEY	21
#define EXIT_FAIL_MAP_FILE	22
#define EXIT_FAIL_MAP_FS	23
#define EXIT_FAIL_IP		30
#define EXIT_FAIL_PORT		31
#define EXIT_FAIL_BPF		40
#define EXIT_FAIL_BPF_ELF	41
#define EXIT_FAIL_BPF_RELOCATE	42

static int verbose = 0;

/* Export eBPF map for IPv4 blacklist as a file
 * Gotcha need to mount:
 *   mount -t bpf bpf /sys/fs/bpf/
 */
static const char *file_blacklist_ipv4 = "/sys/fs/bpf/blacklistv4";
static const char *file_blacklist_ipv6 = "/sys/fs/bpf/blacklistv6";
static const char *file_verdict   = "/sys/fs/bpf/verdict_cnt";
static const char *file_blacklist_ipv6_subnet   = "/sys/fs/bpf/blacklistv6subnet";
static const char *file_blacklist_ipv6_subnetcache = "/sys/fs/bpf/blacklistv6subnetcache";

static const char *file_port_blacklist = "/sys/fs/bpf/port_blacklist";
static const char *file_port_blacklist_count[] = {
	"/sys/fs/bpf/port_blacklist_drop_count_tcp",
	"/sys/fs/bpf/port_blacklist_drop_count_udp"
};
#ifdef DEBUG
static const char *file_reasons   = "/sys/fs/bpf/verdict_reasons";
#endif
#ifdef LONGTERM 
static const char *file_blacklist_ipv4_nodelete = "/sys/fs/bpf/blacklistv4_nodelete";
static const char *file_blacklist_ipv6_nodelete = "/sys/fs/bpf/blacklistv6_nodelete";
#endif

#if defined LONGTERM && defined SUBNET
static const char *file_blacklist_ipv6_subnet_nodelete   = "/sys/fs/bpf/blacklistv6subnet_nodelete";
#endif

// TODO: create subdir per ifname, to allow more XDP progs

/* gettime returns the current time of day in nanoseconds.
 * Cost: clock_gettime (ns) => 26ns (CLOCK_MONOTONIC)
 *       clock_gettime (ns) =>  9ns (CLOCK_MONOTONIC_COARSE)
 */
#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
uint64_t gettime(void);

/* Blacklist operations */
#define ACTION_ADD	1
#define ACTION_DEL	2

enum {
	DDOS_FILTER_TCP = 0,
	DDOS_FILTER_UDP,
	DDOS_FILTER_MAX
};

static int blacklist_modify(int fd, char *ip_string, unsigned int action, unsigned int iptype);


static int blacklist_port_modify(int fd, int countfd, int dport, unsigned int action, int proto);

// Subnet blocking V1
/*
static int blacklist_subnet_modify(int fd, char *ip_string, unsigned int action)
*/
// Subnet blocking V2
static int blacklist_subnet_modify(int fd_cache,int fd_subnetblacklist, char *ip_string, unsigned int action);

#endif
