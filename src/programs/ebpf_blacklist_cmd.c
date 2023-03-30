/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
    Copyright(c) 2017 Andy Gospodarek, Broadcom Limited, Inc.
 */
static const char *__doc__=
 " XDP ddos01: command line tool";
  
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <bpf.h>
#include <libbpf.h>
#include <sys/resource.h>
#include <getopt.h>
#include <time.h>
#include <arpa/inet.h>
#include <argp.h>
#include <stdint.h>

#include <ebpf_utils.h>

#define DDOS_FILTER_MAX 2
#define XDP_ACTION_MAX (XDP_PASS + 1)
#define XDP_ACTION_MAX_STRLEN 11
#define XDP_REASONS_MAX 17
#define NANOSEC_PER_SEC 1000000

static const char *xdp_action_names[XDP_ACTION_MAX] = {
	[XDP_ABORTED]	= "XDP_ABORTED",
	[XDP_DROP]	= "XDP_DROP",
	[XDP_PASS]	= "XDP_PASS",
};

static const char *xdp_reasons_names[XDP_REASONS_MAX] = {
	[0] = "ETH. INCOMPL. HEAD",
	[1] = "ETH. NO 802.3",
	[2] = "ETH. INCOMPL. 1ST VLAN",
	[3] = "ETH. INCOMPL. 2ND VLAN",
	[4] = "ETH. PROT. NO IPv4",
	[5] = "IPv4 INCOMPL. HEAD",
	[6] = "IPv4 SOURCE BLOCKED",
	[7] = "L4 PROT. NOT TCP/UDP",
	[8] = "TCP/UDP INCOMPL. HEAD",
	[9] = "TCP/UDP DEST. PORT NOT BLOCKED FOR PROT.",
	[10] = "TCP/UDP DEST. PORT BLOCKED FOR PROT.",
	[11] = "IPv6 INCOMPL. HEAD",
	[12] = "IPv6 SOURCE BLOCKED",
	[13] = "IPv6 /64 SUBNET BLOCKED",
	[14] = "IPv6 EXT. HEAD/PROT.>143: UNASSIGNED/EXPER.",
	[15] = "IPv6 INCOMPL. EXT. HEAD",
	[16] = "IPv6 TOO MANY EXT. HEAD"
};
		
static const char *xdp_action4reasons_names[XDP_REASONS_MAX] = {
	[0] = "XDP_ABORTED",
	[1] = "XDP_PASS",
	[2] = "XDP_ABORTED",
	[3] = "XDP_ABORTED",
	[4] = "XDP_PASS",
	[5] = "XDP_ABORTED",
	[6] = "XDP_DROP",
	[7] = "XDP_PASS",
	[8] = "XDP_ABORTED",
	[9] = "XDP_PASS",
	[10] = "XDP_DROP",
	[11] = "XDP_ABORTED",
	[12] = "XDP_DROP",
	[13] = "XDP_DROP",
	[14] = "XDP_DROP",
	[15] = "XDP_ABORTED",
	[16] = "XDP_DROP"
};

const char *argp_program_version = "arp 1.0";
const char *argp_program_bug_address = "<bugs@arp.com>";
static char doc[] = "ARP - A program to manage the ARP cache";
static char args_doc[] = "";
static struct argp_option options[] = {
    {"add", 'a', 0, 0, "Add an IP address to the blacklist.", 0},
    {"rem", 'r', 0, 0, "Remove an IP address from the blacklist cache.", 0},
    {"stats", 's', 0, 0, "Display statistics about the blacklist cache.", 0},
    {"write", 'w', 0, 0, "Write stats to file", 0},
    {"timeout", 't', "SECONDS", OPTION_ARG_OPTIONAL, "Specify the timeout value for  entries.", 0},
    {"list", 'l', 0, 0, "List all entries in the blacklist.", 0},
    {"load", 'i', 0, 0, "List all entries in the blacklist.", 0},
    {"detach", 'd', 0, 0, "List all entries in the blacklist.", 0},
    {0}
};

struct arguments 
{
    bool add, del, stats, list;
    char *ip, *sec, *udp_dport, *tcp_dport;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;
    switch (key) {
        case 'h':
            argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
            exit(0);
        case 'a':
            arguments->add = 1;
            break;
        case 'd':
            arguments->del = 1;
            break;
        case 's':
            arguments->stats = 1;
            break;
        case 'l':
            arguments->list = 1;
            break;
        case 'i':
            arguments->ip = arg;
            break;
        case 't':
            arguments->sec = arg;
            break;
        case 'u':
            arguments->udp_dport = arg;
            break;
        case 'p':
            arguments->tcp_dport = arg;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const char *action2str(int action)
{
	if (action < XDP_ACTION_MAX)
		return xdp_action_names[action];
	return NULL;
}


static const char *reason2str(int reason)
{
	if (reason < XDP_REASONS_MAX)
		return xdp_reasons_names[reason];
	return NULL;
}

static const char *reason2actionstr(int reason)
{
	if (reason < XDP_REASONS_MAX)
		return xdp_action4reasons_names[reason];
	return NULL;
}

struct record 
{
	u_int64_t counter;
	u_int64_t timestamp;
};
struct record_cpu
{
	u_int64_t counter *;
	u_int64_t timestamp;
};
struct stats_record_cpu
{
	struct record_cpu xdp_action[XDP_ACTION_MAX];
};
struct stats_record 
{
	struct record xdp_action[XDP_ACTION_MAX];
};
struct reasons_record 
{
	struct record xdp_reasons[XDP_REASONS_MAX];
};

static uint64_t get_key32_value64_percpu(int fd, uint32_t key)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	int nr_cpus = libbpf_num_possible_cpus(); 
	uint64_t values[nr_cpus];
	uint64_t sum = 0;
	int i;
	//printf("fd: %d\n",fd); 
	//printf("Key is: %X\n",key);
	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: get_key32_value_64_percpu: bpf_map_lookup_elem failed key:0x%X, errno: %d\n, %s\n", key,errno,strerror(errno));
		//	return 0;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
	  //	  printf("Value for cpu %d: %lld\n",i,values[i]);
	  sum += values[i];
	}
	return sum;
}
static uint64_t get_key64_value64_percpu(int fd, uint64_t key)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	int nr_cpus = libbpf_num_possible_cpus();
	uint64_t values[nr_cpus];
	uint64_t sum = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%llX\n", key);
		return 0;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum += values[i];
	}
	return sum;
}
static uint64_t get_key128_value64_percpu(int fd, __uint128_t key)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	int nr_cpus = libbpf_num_possible_cpus();
	uint64_t values[nr_cpus];
	uint64_t sum = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%llX%llX\n", (uint64_t)key,(uint64_t)(key<<64));
		return 0;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum += values[i];
	}
	return sum;
}

static void stats_print_headers(void)
{
	/* clear screen */
	printf("\033[2J");
	printf("%-12s %-25s %-18s %-9s\n",
	       "XDP_action", "packets", "packets/period", "period/sec");
}

static void reasons_print_headers(void)
{

	printf("\n%-46s %-25s %-10s %-18s%-9s\n",
	       "Reason","action", "packets", "packets/period", "period/sec");
}

static void reasons_print(struct reasons_record *record,
			struct reasons_record *prev)
{
	int i;

	for (i = 0; i < XDP_REASONS_MAX; i++) {
		struct record *r = &record->xdp_reasons[i];
		struct record *p = &prev->xdp_reasons[i];
		uint64_t period  = 0;
		uint64_t packets = 0;
		double pps = 0;
		double period_ = 0;

		if (p->timestamp) {
		  packets = r->counter; //- p->counter;
		  //printf("R counter : %d ", r->counter);
		  period  = r->timestamp - p->timestamp;
		  //printf("Period: %lld,now: %lld, then: %lld ",period, r->timestamp , p->timestamp);
		  if (period > 0) {
				period_ = ((double) period / NANOSEC_PER_SEC);
				pps = (r->counter - p->counter) / period_;
			}
		}

		if (packets==0){
		  printf("%-46s %-12s %'-25llu %'-18.0f %f \n", reason2str(i), reason2actionstr(i),packets, pps, period_);
		}
		else{
		  printf("%-46s %-12s %'-25llu %'-18.0f %f\n",
			 reason2str(i), reason2actionstr(i), packets, pps, period_);
		}
	}
}

static void stats_print(struct stats_record *record,
			struct stats_record *prev)
{
	int i;

	for (i = 0; i < XDP_ACTION_MAX; i++) {
		struct record *r = &record->xdp_action[i];
		struct record *p = &prev->xdp_action[i];
		uint64_t period  = 0;
		uint64_t packets = 0;
		double pps = 0;
		double period_ = 0;

		if (p->timestamp) {
		  packets = r->counter;//; - p->counter;
			period  = r->timestamp - p->timestamp;
			//printf("PEriod: %lld ", period); 
			if (period > 0) {
				period_ = ((double) period / NANOSEC_PER_SEC);
				pps = (r->counter - p->counter) / period_;
			}
		}
		/*if (packets==0){
                  printf("\n%-12s %'-25llu %'-18.0f %f ", action2str(i), packets, pps, period_);
                }
                else{*/
		  printf("\n%-12s %'-25llu %'-18.0f %f",
			 action2str(i),packets, pps, period_);
	//	}
	}
}

static void stats_print_cpu(struct stats_record_cpu *record, struct stats_record_cpu *prev)
{
int i,j;
int nr_cpus = libbpf_num_possible_cpus();
	printf("\n");
	for (i = 0; i < XDP_ACTION_MAX; i++) {
		struct record_cpu *r = &record->xdp_action[i];
		struct record_cpu *p = &prev->xdp_action[i];
		uint64_t period  = 0;
		uint64_t packets = 0;
		double pps[nr_cpus];
		double period_ = 0;
		printf("%-12s\n",action2str(i));
		printf("%-8s;%-25s;%-18s;%s\n","CPU","packets", "packets/period", "period/sec");
		for(j = 0;j<nr_cpus;j++){
			if (p->timestamp) {
			packets = r->counter[j];//; - p->counter;
				period  = r->timestamp - p->timestamp;
				//printf("PEriod: %lld ", period); 
				if (period > 0) {
					period_ = ((double) period / NANOSEC_PER_SEC);
					pps[j] = (r->counter[j] - p->counter[j]) / period_;
				}
			}
			if (packets==0){
                  printf("%-8d;%'-25llu;%'-18.0f;%f \n", j, packets, pps[j], period_);
                }
                else{
			printf("%-8d;%'-25llu;%'-18.0f;%f\n",
				j,packets, pps[j], period_);
				}
		}
		printf("\n");
	}

}
static void stats_collect(int fd, struct stats_record *rec)
{
	int i;

	for (i = 0; i < XDP_ACTION_MAX; i++) {
		rec->xdp_action[i].timestamp = gettime();
		rec->xdp_action[i].counter = get_key32_value64_percpu(fd, i);
	}
}
static void stats_collect_cpu(int fd, struct stats_record_cpu *rec)
{
	int i,j;
	int nr_cpus = libbpf_num_possible_cpus();
	uint64_t values[nr_cpus];
	for (i = 0; i < XDP_ACTION_MAX; i++) {
		if ((bpf_map_lookup_elem(fd, &i, values)) != 0) {
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem failed key:0x%X, setting -1\n", i);
			for(j=0;j<nr_cpus;j++){
				rec->xdp_action[i].counter[j] =-1;
			}
		}
		rec->xdp_action[i].timestamp = gettime();
		for(j=0;j<nr_cpus;j++){
			rec->xdp_action[i].counter[j] = values[j];
		}
	}
}
static void reasons_collect(int fd, struct reasons_record *rec)
{
	int i;

	for (i = 0; i < XDP_REASONS_MAX; i++) {
		rec->xdp_reasons[i].timestamp = gettime();
		rec->xdp_reasons[i].counter = get_key32_value64_percpu(fd, i);
	}
}


static void stats_poll(int interval)
{
	struct stats_record record_st, prev_st;
	struct reasons_record record_re, prev_re;
	struct stats_record_cpu record_cpu, prev_cpu;
	int fd;

	memset(&record_st, 0, sizeof(record_st));
	memset(&record_re, 0, sizeof(record_re));
	memset(&record_cpu, 0, sizeof(record_cpu));
	/* Trick to pretty printf with thousands separators use %' */
		stats_print_headers();

	while (1) {
 
		memcpy(&prev_st, &record_st, sizeof(record_st));
		memcpy(&prev_cpu, &record_cpu, sizeof(record_cpu));
		fd = open_bpf_map(file_verdict);
		//stats_print_headers();
		stats_collect(fd, &record_st);
		stats_print(&record_st, &prev_st);
		//stats_print_headers_cpu();
	
		sleep(interval);
		close(fd);
	
	}
	/* Not reached, but (hint) remember to close fd in other code */
	//close(fd);
}

static void blacklist_print_ipv4(__u32 ip, __u64 count)
{
	char ip_txt[INET_ADDRSTRLEN] = {0};
 
	/* Convert IPv4 addresses from binary to text form */
	if (!inet_ntop(AF_INET, &ip, ip_txt, sizeof(ip_txt))) {
		fprintf(stderr,
			"ERR: Cannot convert u32 IP:0x%X to IP-txt\n", ip);
		exit(EXIT_FAIL_IP);
	}
	printf("\n\t\"%s\" : %llu", ip_txt, count);
}

static void blacklist_print_ipv6(unsigned __int128 ip, __u64 count)
{
	char ip_txt[INET6_ADDRSTRLEN] = {0}; 
 
	/* Convert IPv6 addresses from binary to text form */
	if (!inet_ntop(AF_INET6, &ip, ip_txt, sizeof(ip_txt))) {
		fprintf(stderr,
			"ERR: Cannot convert u128 IP:0x%llX%llX to IP-txt\n", (__u64)ip,(__u64)(ip<<64));
		exit(EXIT_FAIL_IP);
	}
	printf("\n\t\"%s\" : %llu", ip_txt, count);
}

static void blacklist_print_proto(int key, __u64 count)
{
	printf("\t\"%s\" : %llu", xdp_proto_filter_names[key], count);
}

static void blacklist_print_port(int key, __u32 val, int countfds[]){
	int i;
	__u64 count;

	printf("\n\t\"%d\" : ", key);
	for (i = 0; i < DDOS_FILTER_MAX; i++) {
		if (val & (1 << i)) {

			count = get_key32_value64_percpu(countfds[i], key);
			blacklist_print_proto(i, count);
		}
	}
}

static void blacklist_list_all_ipv4(int fd)
{
	__u32 key, *prev_key = NULL;
	__u64 value;

	while (bpf_map_get_next_key(fd, prev_key, &key) == 0) {
		value = get_key32_value64_percpu(fd, key);
		blacklist_print_ipv4(key, value);
		prev_key = &key;
	}
}

static void blacklist_list_all_ipv6(int fd)
{
	unsigned __int128 key, *prev_key = NULL;
	__u64 value;

	while (bpf_map_get_next_key(fd, prev_key, &key) == 0) {
		value = get_key128_value64_percpu(fd, key);
		blacklist_print_ipv6(key, value);
		prev_key = &key;
	}
	
}
static void blacklist_print_ipv6subnets(__u64 ip, __u64 count)
{
	char ip_txt[INET6_ADDRSTRLEN] = {0}; 
 
	/* Convert IPv6 addresses from binary to text form */
	if (!inet_ntop(AF_INET6, &ip, ip_txt, sizeof(ip_txt))) {
		fprintf(stderr,
			"ERR: Cannot convert u64 IPv6subnet:0x%llX to IP-txt\n", ip);
		exit(EXIT_FAIL_IP);
	}
	printf("\n\t\"%s\" : %llu", ip_txt, count);
}
static void blacklist_list_all_ipv6subnets(int fd)
{
	__u64 key, *prev_key = NULL;
	__u64 value;

	while (bpf_map_get_next_key(fd, prev_key, &key) == 0) {
		value = get_key64_value64_percpu(fd, key);
		blacklist_print_ipv6subnets(key, value);
		prev_key = &key;
	}
	
}
static void blacklist_list_all_ports(int portfd, int countfds[])
{
	__u32 key, *prev_key = NULL;
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 values[nr_cpus];
	while (bpf_map_get_next_key(portfd, prev_key, &key) == 0) {
		if ((bpf_map_lookup_elem(portfd, &key, &values)) != 0) {
			fprintf(stderr,
				"ERR: bpf_map_lookup_elem(%d) failed key:0x%X\n", portfd, key);
		}

		if (values[0]) {
			blacklist_print_port(key, values[0], countfds);
		}
		prev_key = &key;
	}
}



int main (int argc, char **argv)
{
		setlocale(LC_NUMERIC, "");
#	define STR_MAX 40 /* For trivial input validation */
	char _ip_string_buf[STR_MAX] = {};
	char *ip_string = NULL;

	unsigned int action = 0;
	bool stats = false;
	int interval = 1;
	int fd_blacklist;
	#ifdef DEBUG
	int fd_blacklist_debug;
	#endif
	int fd_verdict;
	int fd_port_blacklist;
	int fd_port_blacklist_count;
	int longindex = 0;
	bool do_list = false;
	int opt;
	int dport = 0;
	int proto = IPPROTO_TCP;
	int filter = DDOS_FILTER_TCP;

	while ((opt = getopt_long(argc, argv, "adshi:t:u:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'a':
			action = 1;
			break;
		case 'd':
			action = 2;
			break;
		case 'i':
			if (!optarg || strlen(optarg) >= STR_MAX) {
				printf("ERR: src ip too long or NULL\n");
				goto fail_opt;
			}
			ip_string = (char *)&_ip_string_buf;
			strncpy(ip_string, optarg, STR_MAX);
			break;
		case 'u':
			proto = IPPROTO_UDP;
			filter = DDOS_FILTER_UDP;
		case 't':
			if (optarg)
				dport = atoi(optarg);
			break;
		case 's': /* shared: --stats && --sec */
			stats = true;
			if (optarg)
				interval = atoi(optarg);
			break;
		case 'l':
			do_list = true;
			break;
		case 'h':
		fail_opt:
		default:
			usage(argv);
			return EXIT_FAIL_OPTION;
		}
	}
    
	fd_verdict = open_bpf_map(FILE_VERDICT);

	/* Update blacklist */ 
	if (action) {
		int res = 0; 

		if (!ip_string && !dport) {
			fprintf(stderr,
			  "ERR: action require type+data, e.g option --ip\n");
			goto fail_opt; 
		}

		if (ip_string) { 
			struct in_addr addr4; 
			struct in6_addr addr6;
			//printf("IP String: %s\n",ip_string);
			if (inet_pton(AF_INET, ip_string, &addr4) == 1) {
				fd_blacklist = open_bpf_map(file_blacklist_ipv4);
				res = blacklist_modify(fd_blacklist, ip_string, action,4);
				close(fd_blacklist);
				#ifdef LONGTERM
				if ((action == 1)){
					fd_blacklist_debug = open_bpf_map(file_blacklist_ipv4_debug);
					res = blacklist_modify(fd_blacklist_debug, ip_string, action,4);	
				}
				close(fd_blacklist_debug);
				#endif
			}
			else if (inet_pton(AF_INET6, ip_string, &addr6) == 1) {
				fd_blacklist = open_bpf_map(FILE_BLA);
				res = blacklist_modify(fd_blacklist, ip_string, action,6);
				close(fd_blacklist);
				#ifdef LONGTERM
				if ((action == 1)){
					fd_blacklist_debug = open_bpf_map(file_blacklist_ipv6_debug);
					res = blacklist_modify(fd_blacklist_debug, ip_string, action,6);	
				}
				close(fd_blacklist_debug);
				#endif
			}
			else{
				fprintf(stderr, "ERR: IP address isn't valid IPv4 or IPv6 address %s\n",ip_string);
				close(fd_verdict);
				exit(EXIT_FAIL_IP); 
			}
		} 

		if (dport) {
			fd_port_blacklist = open_bpf_map(file_port_blacklist);
			fd_port_blacklist_count = open_bpf_map(file_port_blacklist_count[filter]);
			res = blacklist_port_modify(fd_port_blacklist, fd_port_blacklist_count, dport, action, proto);
			close(fd_port_blacklist);
			close(fd_port_blacklist_count);
		}
		return res;
	}


	if (do_list) {

        int fd_port_blacklist_count_array[DDOS_FILTER_MAX];
		int i;

		printf("\nIPv4 Blacklist:");
		
		fd_blacklist = open_bpf_map(file_blacklist_ipv4);
		blacklist_list_all_ipv4(fd_blacklist);
		close(fd_blacklist);
		printf("\n\nIPv6 Blacklist:");
		fd_blacklist = open_bpf_map(file_blacklist_ipv6);
		blacklist_list_all_ipv6(fd_blacklist);
		close(fd_blacklist);
		printf("\n\nIPv6 Subnet Blacklist:");
		fd_blacklist = open_bpf_map(file_blacklist_ipv6_subnet);
		blacklist_list_all_ipv6subnets(fd_blacklist);
		close(fd_blacklist);
		printf("\n\nPort Blacklist:");
		fd_port_blacklist = open_bpf_map(file_port_blacklist);
		for (i = 0; i < DDOS_FILTER_MAX; i++)
			fd_port_blacklist_count_array[i] = open_bpf_map(file_port_blacklist_count[i]);
		blacklist_list_all_ports(fd_port_blacklist,  fd_port_blacklist_count_array);
		close(fd_port_blacklist);
		printf("\n");
		for (i = 0; i < DDOS_FILTER_MAX; i++)
		close(fd_port_blacklist_count_array[i]);
	}

	if (stats) {
		stats_poll(interval);
	}  

	close(fd_verdict);
}
