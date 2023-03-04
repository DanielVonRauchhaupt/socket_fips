#define _GNU_SOURCE
#include <argp.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ip_blacklist.skel.h"
#include <linux/if_link.h> /* Need XDP flags */
#include <string.h>
#include <pthread.h>
#include <hs.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <signal.h>
#include <sys/shm.h>
#include <sys/sysinfo.h>


#include <ip_hashtable.h>
#include <ip_llist.h>
#include <io_ipc.h>
#include "blacklist_common.h"

#define RETURN_FAIL (-1)
#define RETURN_SUCC (0)
#define NTHREADS 1
#define WATCHER_COUNT 1

#define DEFAULT_BAN_TIME 60
#define DEFAULT_BAN_THRESHOLD 1
#define DEFAULT_IPC_TYPE DISK
#define DEFAULT_IFACE "enp24s0f0np0"
#define DEFAULT_LOG "udpsvr.log"

#define UNUSED(x)(void)(x)

#define DEFAULT_MATCH_REGEX "\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} client (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|[a-fA-F0-9:]+) exceeded request rate limit"
#define DEFAULT_IP_REGEX "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|[a-fA-F0-9:]+)"

#define LOGBUF_SIZE 256

// global variables
static volatile sig_atomic_t server_running = true;
static bool verbose = false;
static pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ip_hashtable_t * htable;
static struct ip_llist_t * banned_list; 
static enum ipc_type_t ipc_type = DEFAULT_IPC_TYPE;
static uint8_t thread_count = NTHREADS;
static uint16_t bantime = DEFAULT_BAN_TIME;
static uint16_t limit = DEFAULT_BAN_THRESHOLD;
static bool matching = false;
static char * shm_key;
static char * logfile = DEFAULT_LOG;
static char * regex = DEFAULT_MATCH_REGEX;
static char * interface = DEFAULT_IFACE;
static int ipv4_ebpf_map;
static int ipv6_ebpf_map;

#define NANOSECONDS_PER_MILLISECOND 1000000
#define TIMEOUT 500 * NANOSECONDS_PER_MILLISECOND

// Structs

struct unban_targs_t{
	uint32_t wakeup_interval;
	uint64_t unban_count;
	int retval;
};

union ip_addr_t
{
	uint32_t ipv4;
	__uint128_t ipv6;
};


struct watcher_targs_t {
	struct shmrbuf_reader_arg_t * ipc_args;
	uint8_t thread_id;
	uint32_t wakeup_interval;
	uint64_t rcv_count;
	uint64_t ban_count;
	int retval;
};

struct regex_context_t {
	char ip_str_buf[LOGBUF_SIZE];
	union ip_addr_t ip_addr;
	int8_t domain;
};

// Argparse

const char *argp_program_version = "simplefail2ban 0.0";
static const char argp_program_doc[] =
"simplefail2ban.\n"
"\n"
"A minimal eBPF based IPS for testing purposes";

static char args_doc[] = "INTERFACE";

static const struct argp_option opts[] = {

	{ "disk", 'd', "LOGFILE", 0, "Specifies disk as the chosen ipc type", 0},
	{"shm", 's', "KEY", 0, "Specifies shared memory as the ipc type", 0},
	{"threads", 't', "N", 0, "Specify the number of banning threads to use",0},
	{ "limit", 'l', "N", 0, "Number of matches before a client is banned", 0},
	{ "bantime", 'b', "N", 0, "Number of seconds a client should be banned", 0},
	{ "regex", 'r', "REGEX", 0, "Regular Expression for matching", 0},
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output. Errors will be printed regardless", 0},
	{0},
};

struct arguments
{
  bool ipc_set;
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;

	switch (key) {
	
	case 'd':

		if(arguments->ipc_set){
			fprintf(stderr,"Only one IPC type can be specified\n");
			argp_usage(state);
		}

		arguments->ipc_set = true;
		ipc_type = DISK;

		if(arg != NULL){
			logfile = arg;
		}

		break;

	case 's':

		if(arguments->ipc_set){
			fprintf(stderr,"Only one IPC type can be specified\n");
			argp_usage(state);
		}

		arguments->ipc_set = true;
		ipc_type = SHM;

		if(arg == NULL){
			fprintf(stderr,"SHM requires a key parameter\n");
			argp_usage(state);
		}

		shm_key = arg;

		break;

	case 't':
            
            thread_count = (uint8_t) strtol(arg,NULL,10);
            
            if(get_nprocs() < thread_count){
                thread_count = get_nprocs();
                fprintf(stderr,"Using maximum number of banning threads = %d\n",thread_count);
            }

            if(thread_count == 0){
                thread_count = 1;
                fprintf(stderr,"Minimum 1 banning thread required\n");
            }

            break;

	case 'l':
            
            limit = (uint16_t) strtol(arg,NULL,10);

            break;

	case 'b':
            
            bantime = (uint16_t) strtol(arg,NULL,10);

            break;

	case 'r':

			matching = true;

			if(arg != NULL){
				regex = arg;
			}

            break;

	case 'v':
		verbose = true;
		break;

	case ARGP_KEY_ARG:
      	if (state->arg_num >=2 ){
			fprintf(stderr, "Too many arguments. See usage\n");
			argp_usage (state);
	  	}
		
		interface = arg;

		break;
	case ARGP_KEY_END:
      if (state->arg_num < 1){
		interface = DEFAULT_IFACE;
	  }
	 
      break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}
static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.args_doc = args_doc,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}


static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int ebpf_cleanup(const char * device, bool unpin){

    struct ip_blacklist_bpf * skel;

    //printf("device is %s\n",arguments.device);
	/* Check if device exists */
	int ifindex = if_nametoindex(device);
	if (ifindex == 0){
 		fprintf(stderr,"Looking up device index for device %s failed: %s\n",device,strerror(errno));
		return EXIT_FAILURE;
	}

    /* Detach, indpendent of program. Call succeeds even on an empty device */
	int xdp_flags = 0;
	xdp_flags |= XDP_FLAGS_DRV_MODE;
	int err = bpf_xdp_attach(ifindex,-1,xdp_flags,NULL);
	if (err) {
		fprintf(stderr, "Failed to detach eBPF program in xdp driver mode from device: %s. See libbpf error. Doing skb mode instead.\n",device);

	}
	xdp_flags = 0;
	xdp_flags |= XDP_FLAGS_SKB_MODE;
	err = bpf_xdp_attach(ifindex,-1,xdp_flags,NULL);
	if (err) {
		fprintf(stderr, "Failed to detach eBPF program in xdp skb mode from device: %s. See libbpf error. Exiting.\n",device);
		return RETURN_FAIL;
	}
	if(verbose){printf("Detached eBPF program from device %s.\n",device);}
	
    if(unpin){

        skel = ip_blacklist_bpf__open();
        if (!skel) {
            fprintf(stderr, "Failed to open BPF skeleton\n");
        return RETURN_FAIL;
        }
        err = bpf_object__unpin_maps(skel->obj,NULL);
        if (err) {
            fprintf(stderr, "Failed to unpin maps in /sys/fs/bpf: %s\n",strerror(errno));
        }
        if(verbose){printf("Clean up successful. Maps unlinked.\n");}

    }
    
    return RETURN_SUCC;
		
}

/* Prints a formatted string to a mutex locked file descriptor */
void sync_message(const char * fmt, pthread_mutex_t * lock, FILE * fp, va_list targs){
    pthread_mutex_lock(lock);
    vfprintf(fp, fmt, targs);
    pthread_mutex_unlock(lock);
}

/* Prints a formatted message to stdout (Thread safe) */
void info_msg(const char* fmt,...){
    va_list targs;
    va_start(targs, fmt);
    sync_message(fmt,&stdout_lock,stdout,targs);
    va_end(targs);
}

/* Prints a formatted message to stderr (Thread safe) */
void error_msg(const char * fmt,...){
    va_list targs;
    va_start(targs, fmt);
    sync_message(fmt,&stderr_lock,stderr,targs);
    va_end(targs);
}

uint64_t gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}


static int map_error(const char * ip_string, unsigned long long subnet_key,char *strerror_buf, int strerror_size){
	error_msg(
			"IP:%s key:0x%016llX (%s)\n",
			ip_string,subnet_key, strerror_r(errno,strerror_buf,strerror_size)); 
	return EXIT_FAIL_MAP_KEY;
}

int blacklist_subnet_modify(int fd_cache,int fd_subnetblacklist, __uint128_t * ip6addr, unsigned int action, int nr_cpus, char * strerror_buf, int strerror_size)
{
	__u64 values_prev[nr_cpus];
	__u64 values_next[nr_cpus];
	__u64 value_prev = 0;
	__u64 value_next = 0;

	if(memset(values_prev, 0,  sizeof(__u64) * nr_cpus) == NULL || memset(values_next, 0,  sizeof(__u64) * nr_cpus) == NULL){
		error_msg("Memset error in blacklist_subnet_modify : Line %d\n",__LINE__);
	}
	__u64 subnet_key = (__u64) *ip6addr;
	int res;
	char ip6_str_buf[INET6_ADDRSTRLEN];

	switch (action)
	{
	case ACTION_ADD:
		res = bpf_map_lookup_elem(fd_cache,&subnet_key,&value_prev);
		if (res==-1){
			value_next = 1;
			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_NOEXIST);
			if ( res == -1){
				if(verbose){
					inet_ntop(AF_INET6,(void *)ip6addr,ip6_str_buf,INET6_ADDRSTRLEN);
					return map_error(ip6_str_buf,subnet_key,strerror_buf,strerror_size);	
				}
				return EXIT_FAIL_MAP_KEY;		
			}
		}

		else{
			value_next = value_prev +1;
			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_EXIST);
			if ( res == -1){
				if(verbose){
					inet_ntop(AF_INET6,(void *)ip6addr,ip6_str_buf,INET6_ADDRSTRLEN);
					return map_error(ip6_str_buf,subnet_key,strerror_buf,strerror_size);	
				}
				return EXIT_FAIL_MAP_KEY;			
			}

			if (value_next == SUBNET_THRESHOLD){
				res = bpf_map_update_elem(fd_subnetblacklist,&subnet_key,&values_next,BPF_NOEXIST);
				if ( res == -1){
					if(verbose){
						inet_ntop(AF_INET6,(void *)ip6addr,ip6_str_buf,INET6_ADDRSTRLEN);
						return map_error(ip6_str_buf,subnet_key,strerror_buf,strerror_size);	
					}
					return EXIT_FAIL_MAP_KEY;				
				}
			}

		}

		break;

	case ACTION_DEL:

		res = bpf_map_lookup_elem(fd_cache,&subnet_key,&value_prev);
		if ( res == -1){
			if(verbose){
					inet_ntop(AF_INET6,(void *)ip6addr,ip6_str_buf,INET6_ADDRSTRLEN);
					return map_error(ip6_str_buf,subnet_key,strerror_buf,strerror_size);	
				}
			return EXIT_FAIL_MAP_KEY;
		}
		value_next = value_prev -1;
		if (value_next==0){
			res = bpf_map_delete_elem(fd_cache, &subnet_key);
			if ( res == -1){
				if(verbose){
					inet_ntop(AF_INET6,(void *)ip6addr,ip6_str_buf,INET6_ADDRSTRLEN);
					return map_error(ip6_str_buf,subnet_key,strerror_buf,strerror_size);	
				}
				return EXIT_FAIL_MAP_KEY;	
			}

			if(verbose){info_msg("Action del, looking up subnet blacklist  element\n");}

			res = bpf_map_lookup_elem(fd_subnetblacklist,&subnet_key,&value_next);
			if(res == 0){ 

				if(verbose){info_msg("Action del, del subnet blacklist  element\n");}

				res = bpf_map_delete_elem(fd_subnetblacklist,&subnet_key);

				if ( res == -1){
					if(verbose){
						inet_ntop(AF_INET6,(void *)ip6addr,ip6_str_buf,INET6_ADDRSTRLEN);
						return map_error(ip6_str_buf,subnet_key,strerror_buf,strerror_size);	
					}
					return EXIT_FAIL_MAP_KEY;
				}
			}
		}
		else{
			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_EXIST);
			if ( res == -1){
				if(verbose){
					inet_ntop(AF_INET6,(void *)ip6addr,ip6_str_buf,INET6_ADDRSTRLEN);
					return map_error(ip6_str_buf,subnet_key,strerror_buf,strerror_size);	
				}
				return EXIT_FAIL_MAP_KEY;
			}
		}

		break;
		
	
	default:
		error_msg("ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	 
	if (verbose){
		
		inet_ntop(AF_INET6,(void *)ip6addr,ip6_str_buf,INET6_ADDRSTRLEN);
		error_msg(
		"%s() IP:%s key:0x%016llX\n", __func__, ip6_str_buf, subnet_key);
		}
	res = bpf_map_lookup_elem(fd_cache, &subnet_key,&value_next);

	if(verbose){info_msg("Values changed to: %llu from %llu\n",value_next, value_prev);}

	return EXIT_OK;
}

int blacklist_modify(int fd, void * ip_addr, unsigned int action, unsigned int domain,int nr_cpus, char * strerror_buf, int strerror_size)
{
	__u64 values[nr_cpus];
	int res;
	char ip_str_buf[INET6_ADDRSTRLEN];

	if(memset(values, 0, sizeof(__u64) * nr_cpus) == NULL){
		error_msg("Memset Error in blacklist modify : Line %d\n",__LINE__);
	}

	switch (action)
	{
	case ACTION_ADD:
		if (domain == AF_INET){
		res = bpf_map_update_elem(fd, (uint32_t *)ip_addr, values, BPF_NOEXIST);
		}
		else {
		res = bpf_map_update_elem(fd, (__uint128_t *)ip_addr, values, BPF_NOEXIST);
		}
	break;

	case ACTION_DEL:
		if (domain == AF_INET){
		res = bpf_map_delete_elem(fd, (uint32_t *)ip_addr);
		}
		else{
		res = bpf_map_delete_elem(fd, (__uint128_t *)ip_addr);
		}
	break;

	default:
		error_msg("ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	if (res != 0) { 
		if (domain == AF_INET){
			inet_ntop(AF_INET,ip_addr,ip_str_buf,INET6_ADDRSTRLEN);
			if(verbose){error_msg(
			"%s() line %d IP:%s key:0x%X errno(%d/%s)",
			__func__,__LINE__, ip_str_buf, (__u32)*((__u32 *)ip_addr), errno, strerror_r(errno,strerror_buf,strerror_size));}
					}
		else{
			inet_ntop(AF_INET6,ip_addr,ip_str_buf,INET6_ADDRSTRLEN);
			if(verbose){error_msg(
			"%s() line %d IP:%s key:0x%llX%llX errno(%d/%s)",
			__func__,__LINE__, ip_str_buf, (__u64)*((__uint128_t *)ip_addr),(__u64)(*((__uint128_t *)ip_addr)>>64), errno,strerror_r(errno,strerror_buf,strerror_size));} 	
				}
		

		if (errno == 17) {
			if(verbose){error_msg("address already in blacklist\n");}
			return EXIT_OK;
		}
		error_msg("\n");
		return EXIT_FAIL_MAP_KEY;
	}
	if (verbose){
		if (domain == AF_INET){
				inet_ntop(AF_INET,ip_addr,ip_str_buf,INET6_ADDRSTRLEN);
				if(verbose){error_msg(
				"%s() line %d IP:%s key:0x%X\n", __func__,__LINE__, ip_str_buf, (__u32)*((__u32 *)ip_addr));}
		}
		else {
			inet_ntop(AF_INET6,ip_addr,ip_str_buf,INET6_ADDRSTRLEN);
			if(verbose){error_msg(
			"%s() line %d IP:%s key:0x%llX%llX\n", __func__,__LINE__, ip_str_buf, (__u64)*((__uint128_t *)ip_addr),(__u64)(*((__uint128_t *)ip_addr)>>64));}
			}
	}	
	return EXIT_OK;
}

int blacklist_port_modify(int fd, int countfd, int dport, unsigned int action, int proto, int nr_cpus, char * strerror_buf, int strerror_size)
{
	__u64 curr_values[nr_cpus];
	__u64 stat_values[nr_cpus];
	__u64 value;
	__u32 key = dport;
	int res; 
	int i;

	if (action != ACTION_ADD && action != ACTION_DEL)
	{
		error_msg("ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	if (proto == IPPROTO_TCP)
		value = 1 >> DDOS_FILTER_TCP;
	else if (proto == IPPROTO_UDP)
		value = 1 >> DDOS_FILTER_UDP;
	else {
		error_msg("ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	if(memset(curr_values, 0, sizeof(__u64) * nr_cpus) == NULL){
		error_msg("Memset Error in %s : Line %d\n",__func__,__LINE__);
	}

	if (dport > 65535) {
		error_msg(
			"ERR: destination port \"%d\" invalid\n",
			dport);
		return EXIT_FAIL_PORT;
	}

	if (bpf_map_lookup_elem(fd, &key, curr_values)) {
		error_msg(
			"%s() 1 bpf_map_lookup_elem(key:0x%X) failed errno(%d/%s)",
			__func__, key, errno, strerror_r(errno,strerror_buf,strerror_size));
	}

	if (action == ACTION_ADD) {
		/* add action set bit */
		for (i=0; i<nr_cpus; i++)
			curr_values[i] |= value;
	} else if (action == ACTION_DEL) {
		/* delete action clears bit */
		for (i=0; i<nr_cpus; i++)
			curr_values[i] &= ~(value);
	}

	res = bpf_map_update_elem(fd, &key, &curr_values, BPF_EXIST);

	if (res != 0) { /* 0 == success */
		error_msg(
			"%s() dport:%d key:0x%X value errno(%d/%s)",
			__func__, dport, key, errno, strerror_r(errno,strerror_buf,strerror_size));

		if (errno == 17) {
			error_msg(": Port already in blacklist\n");
			return EXIT_OK;
		}
		error_msg("\n");
		return EXIT_FAIL_MAP_KEY;
	}

	if (action == ACTION_DEL) {
		/* clear stats on delete */
		if(memset(stat_values, 0, sizeof(__u64) * nr_cpus) == NULL){
			error_msg("Memset Error in %s : Line %d\n",__func__,__LINE__);
		}
		res = bpf_map_update_elem(countfd, &key, &stat_values, BPF_EXIST);

		if (res != 0) { /* 0 == success */
			error_msg(
				"%s() dport:%d key:0x%X value errno(%d/%s)",
				__func__, dport, key, errno, strerror_r(errno,strerror_buf,strerror_size));

			error_msg("\n");
			return EXIT_FAIL_MAP_KEY;
		}
	}

	if (verbose)
		error_msg(
			"%s() dport:%d key:0x%X\n", __func__, dport, key);
	return EXIT_OK;
}

static int ebpf_setup(const char * device, bool verbose){

    struct ip_blacklist_bpf *skel;

    /* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to create BPF maps */
	bump_memlock_rlimit();

    //printf("device is %s\n",arguments.device);
	/* Check if device exists */
	int ifindex = if_nametoindex(device);
	if (ifindex == 0){
 		fprintf(stderr,"Looking up device index for device %s failed: %s\n",device,strerror(errno));
		return EXIT_FAILURE;
	}

    unsigned int xdp_fd;

    if((bpf_xdp_query_id(ifindex,0,&xdp_fd)) != -1){
        
        ebpf_cleanup(device,false);
    }

    skel = ip_blacklist_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return EXIT_FAILURE;
	}


	/* Load & verify BPF programs */
	int err = ip_blacklist_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		
	}
	/* Attach xdp */
	int xdp_flags = 0;
	xdp_flags |= XDP_FLAGS_DRV_MODE;
	err = bpf_xdp_attach(ifindex,bpf_program__fd(skel->progs.xdp_prog),xdp_flags,NULL);
	if (err) {
	  if (err == -17){
	    fprintf(stderr, "Failed to attach eBPF program in xdp driver mode for device: %s. See libbpf error: %s. Device already in use in different mode. Trying skb mode.\n",device, strerror(errno));
		}
	  else if(err ==-22){
	    fprintf(stderr, "Failed to attach eBPF program in xdp driver mode for device %s. See libbpf error: %s. Check device MTU. Jumboframes are not supported and throw this error\n",device, strerror(errno));
	  }
	  fprintf(stderr, "Failed to attach eBPF program in xdp driver mode for device: %s. See libbpf error: %s. Doing skb mode instead.\n",device, strerror(errno));
		xdp_flags = 0;
		xdp_flags |= XDP_FLAGS_SKB_MODE;
		err = bpf_xdp_attach(ifindex,bpf_program__fd(skel->progs.xdp_prog),xdp_flags,NULL);
		if (err) {
			if (err == -17){
				fprintf(stderr, "Failed to attach eBPF program in xdp driver mode for device: %s. See libbpf error. Device already in use.\n",device);
				ip_blacklist_bpf__destroy(skel);
                return RETURN_FAIL;
		}
			fprintf(stderr, "Failed to attach eBPF program in xdp skb mode for device: %s. See libbpf error. Exiting.\n",device);
			ip_blacklist_bpf__destroy(skel);
            return RETURN_FAIL;
		}
	if(verbose){printf("Attached program onto device %s in skb mode. Maps pinned to /sys/fs/bpf/.\n",device);}
	return 0;
	}

	if(verbose){printf("Attached program onto device %s in driver mode. Maps pinned to /sys/fs/bpf/	.\n",device);}
	return 0;


}

void sig_handler(int signal){
    UNUSED(signal);
    server_running = false;
}


int open_bpf_map(const char *file)
{
	int fd;

	fd = bpf_obj_get(file);
	
	return fd;
}

int8_t block_signals(bool keep){
    sigset_t set;
    if(sigfillset(&set)){
        return RETURN_FAIL;
    }

    if(keep){
        if(sigdelset(&set,SIGINT) || sigdelset(&set,SIGTERM)){
            return RETURN_FAIL;
        }
    }

    if(pthread_sigmask(SIG_BLOCK, &set, NULL)){
        return RETURN_FAIL;
    }

    return RETURN_SUCC;
}


void * unban_thread_routine(void * args){

	struct unban_targs_t * targs = (struct unban_targs_t *) args;
	time_t ts;
	struct timespec timeout = {.tv_sec=0,.tv_nsec=targs->wakeup_interval};
	char strerror_buf[64];
	struct ip_listnode_t * current_tail, * iterator, * prev, * next;
	int retval, nr_cpus = libbpf_num_possible_cpus();

	if(block_signals(true)){
        error_msg("Failed to block signals\n");
    }
    if(signal(SIGINT,sig_handler) == SIG_ERR || signal(SIGTERM,sig_handler) == SIG_ERR){
        char strerror_buf[64];
        error_msg("Failed to set signal handler : %s\n",strerror_r(errno,strerror_buf,64));
    }

	while (server_running)
	{
		time(&ts);

		if(ts == -1){
			error_msg("Failed to obtain timestamp : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
			targs->retval = EXIT_FAIL;
			pthread_exit(&targs->retval);
		}

		if(pthread_mutex_lock(&banned_list->tail_lock)){
			pthread_mutex_unlock(&banned_list->tail_lock);
			error_msg("Failed to claim banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
			targs->retval = EXIT_FAIL;
			pthread_exit(&targs->retval);
		}

		current_tail = banned_list->tail;

		if(pthread_mutex_unlock(&banned_list->tail_lock)){
			error_msg("Failed to claim banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
			targs->retval = EXIT_FAIL;
			pthread_exit(&targs->retval);
		}

		if(current_tail == NULL || banned_list->head == NULL){
			if(current_tail != NULL){
				error_msg("Banned list head is null but list is not empty\n");



			}
		} else {

			iterator = banned_list->head;
			prev = NULL;
			next = NULL;
			bool brk = false;

			while(iterator != NULL){

				if(iterator == current_tail){
					brk = true;
				}

				if((ts - iterator->timestamp) > limit){

					if(brk){
						if(pthread_mutex_lock(&banned_list->tail_lock)){
							pthread_mutex_unlock(&banned_list->tail_lock);
							error_msg("Failed to claim banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
							targs->retval = EXIT_FAIL;
							pthread_exit(&targs->retval);
						}
					}

					switch (iterator->domain)
					{
					case AF_INET:
						
						retval = blacklist_modify(ipv4_ebpf_map,iterator->key,ACTION_DEL,AF_INET,nr_cpus,strerror_buf,sizeof(strerror_buf));
						break;
					
					case AF_INET6:

						retval = blacklist_modify(ipv6_ebpf_map,iterator->key,ACTION_DEL,AF_INET6,nr_cpus,strerror_buf,sizeof(strerror_buf));
						break; 

					default:
						retval = -1;
						error_msg("Invalid domain in banned list %d\n",iterator->domain);
					}

					if(retval < 0){
						error_msg("Error modifying ebf map : error code %d\n",retval);
					} else {
						targs->unban_count++;
					}

					if(brk){
						if(pthread_mutex_unlock(&banned_list->tail_lock)){
							error_msg("Failed to release banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
								targs->retval = EXIT_FAIL;
								pthread_exit(&targs->retval);
						}

						if(prev == NULL){
							banned_list->head = NULL;
						}

						if(iterator->next == NULL){
							banned_list->tail = NULL;
						}

						if((retval = ip_llist_remove(&iterator,prev)) < 0){
							error_msg("Error removing tail node from banned list : error code %d\n",retval);
						}

						break;
					}

					next = iterator->next;

					if((retval = ip_llist_remove(&iterator,prev)) < 0){
						error_msg("Error removing node from banned list : error code %d\n",retval);
					}

					iterator = next;

					if(prev == NULL){
						banned_list->head = next;
					}
				}

				else {
					prev = iterator;
					iterator = iterator->next;
				}

			}

		}

		nanosleep(&timeout,NULL);


	}
	
	targs->retval = EXIT_SUCCESS;
	return &targs->retval;

}

int regex_match_handler(unsigned int id, unsigned long long from, unsigned long long to,
                  unsigned int flags, void *ctx){

	UNUSED(flags);
	struct regex_context_t * context = (struct regex_context_t *)ctx;

	if(id != 1){
		return 0;
	}

	context->ip_str_buf[to] = '\0';

	if (inet_pton(AF_INET,&context->ip_str_buf[from],&context->ip_addr.ipv4) == 1) {
		context->domain = AF_INET;
        return 1;
    } else if (inet_pton(AF_INET6, &context->ip_str_buf[from],&context->ip_addr.ipv6) == 1) {
		context->domain = AF_INET6;
        return 1;
    } else {
		context->domain = -1;
		return 0;
    }
}


void * ban_thread_routine(void * args){

	struct watcher_targs_t * targs = (struct watcher_targs_t *)args;

	hs_database_t * database;
	hs_compile_error_t * compile_error;
	hs_scratch_t * scratch = NULL; 
	struct regex_context_t reg_context;
	struct timespec tspec = {.tv_sec=0,.tv_nsec=targs->wakeup_interval};
	int retval, i, buffer_count;
	char strerror_buf[64];
	bool no_read;
	int nr_cpus = libbpf_num_possible_cpus();

	buffer_count = targs->ipc_args->head->segment_count / thread_count;
	buffer_count = ((targs->ipc_args->head->segment_count % thread_count) < targs->thread_id) ? buffer_count + 1 : buffer_count;

	if(memset(&reg_context,0,sizeof(reg_context)) == NULL){
		error_msg("Memset error\n");
	}

	if(block_signals(false)){
        error_msg("Failed to block signals\n");
    }

	if (hs_compile(regex, HS_FLAG_SOM_LEFTMOST, HS_MODE_BLOCK, NULL, &database, &compile_error) != HS_SUCCESS) {
        error_msg("Hyperscan compilation failed with error code %d\n", compile_error->expression);
        hs_free_compile_error(compile_error);
		targs->retval = EXIT_FAIL;
        return &targs->retval;
    } 

    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS) {
        error_msg("Hyperscan allocation of scratch space failed\n");
        hs_free_database(database);
        targs->retval = EXIT_FAIL;
        return &targs->retval;
    }

	while (server_running)
	{
		no_read = true;

		for(i = targs->thread_id; i < buffer_count; i++){
			if((retval = shmrbuf_read(targs->ipc_args,reg_context.ip_str_buf,sizeof(reg_context.ip_str_buf),targs->thread_id)) > 0){

				targs->rcv_count++;
				no_read = false;
				/*
				if((retval=hs_scan(database,reg_context.ip_str_buf,LOGBUF_SIZE,0,scratch,regex_match_handler,&reg_context)) != HS_SCAN_TERMINATED){
					if(retval != HS_SUCCESS){
						error_msg("Hyperscan error for logstring %s : error code %d\n",reg_context.ip_str_buf,retval);
						hs_free_database(database);
						hs_free_scratch(scratch);
						targs->retval = EXIT_FAIL;
						return &targs->retval;
					}
					continue;
				}
				*/

				reg_context.ip_str_buf[retval-1] = '\0';

				if (inet_pton(AF_INET,reg_context.ip_str_buf,&reg_context.ip_addr.ipv4) == 1) {
					reg_context.domain = AF_INET;
				} else if (inet_pton(AF_INET6, reg_context.ip_str_buf,&reg_context.ip_addr.ipv6) == 1) {
					reg_context.domain = AF_INET6;
				} else {
					reg_context.domain = -1;
				}

				switch (reg_context.domain)
				{
				case AF_INET:
					
					retval = ip_hashtable_insert(htable,&reg_context.ip_addr.ipv4,AF_INET);

					break;

				case AF_INET6:

					retval = ip_hashtable_insert(htable,&reg_context.ip_addr.ipv6,AF_INET6);

					break;
				
				case -1:
					if(verbose){error_msg("Invalid address in logstring : %s\n",reg_context.ip_str_buf);}
					continue;
				
				default:
					continue;
				}

				if(retval < 1){
					if(verbose){error_msg("Error in htable query for logstring : %s : Error Code %d\n",reg_context.ip_str_buf,retval);}
					continue;
				}

				if(retval > limit){
					time_t ts = time(NULL);

					switch (reg_context.domain)
					{
					case AF_INET:
						if((retval = ip_llist_append(banned_list,&reg_context.ip_addr.ipv4,&ts,AF_INET)) < 0){
							if(verbose){error_msg("Error appending to banned list for logstring : %s : Error Code %d\n",reg_context.ip_str_buf,retval);}
								continue;
						}
					    retval = blacklist_modify(ipv4_ebpf_map,&reg_context.ip_addr.ipv4,ACTION_ADD,AF_INET,nr_cpus,strerror_buf,sizeof(strerror_buf));
						break;
					
					case AF_INET6:
						if((retval = ip_llist_append(banned_list,&reg_context.ip_addr.ipv6,&ts,AF_INET6)) < 0){
							if(verbose){error_msg("Error appending to banned list for logstring : %s : Error Code %d\n",reg_context.ip_str_buf,retval);}
								continue;
						}
					    retval = blacklist_modify(ipv6_ebpf_map,&reg_context.ip_addr.ipv6,ACTION_ADD,AF_INET6,nr_cpus,strerror_buf,sizeof(strerror_buf));
						break;

					default:
						continue;
					}

					if(retval != EXIT_OK){
						if(verbose){error_msg("Error modifying blacklist : Error code %d\n",retval);}
						no_read = false;
						continue;
					}

					targs->ban_count++;
				
				} 

			}

			else if(retval < 0) {
				if(verbose){error_msg("Error in read function : error code %d\n",retval);}
			}

		}

		if(no_read){
			
			nanosleep(&tspec,NULL);

		}

		continue;

	}
	
	hs_free_database(database);
	hs_free_scratch(scratch);

	targs->retval = EXIT_SUCCESS;
	return &targs->retval;

}




int main(int argc, char **argv){

	UNUSED(file_port_blacklist);
	UNUSED(file_port_blacklist_count);
	UNUSED(file_blacklist_ipv6_subnet);
	UNUSED(file_blacklist_ipv6_subnetcache);
	UNUSED(file_verdict);
	
    struct arguments arguments;
	struct watcher_targs_t * thread_args;
	struct unban_targs_t unban_targs = {.unban_count = 0,.wakeup_interval=TIMEOUT};
	pthread_t * thread_ids;
	int i, retval;
	retval = argp_parse(&argp, argc, argv, 0, NULL, &arguments);
	if (retval == ARGP_ERR_UNKNOWN){
		return retval;
	}
		
	/*
    if(ebpf_setup(interface,false)){
		fprintf(stderr,"ebpf setup failed\n");
		exit(EXIT_FAILURE);
	}

	if((ipv4_ebpf_map = open_bpf_map(file_blacklist_ipv4)) == RETURN_FAIL || (ipv6_ebpf_map = open_bpf_map(file_blacklist_ipv6)) == RETURN_FAIL){
		fprintf(stderr,"ERR: Failed to open bpf map  : %s\n",strerror(errno));
		ebpf_cleanup(interface,true,true);
		exit(EXIT_FAILURE);
	}
	*/

	if((thread_ids = calloc(sizeof(pthread_t),thread_count-1)) == NULL || (thread_args = calloc(sizeof(struct unban_targs_t),thread_count)) == NULL){
		perror("Calloc failed");
		ebpf_cleanup(interface,true);
		exit(EXIT_FAILURE);
	}

	if((retval = ip_hashtable_init(&htable)) < 0)
	{
		fprintf(stderr,"ip_hashtable_init failed with error code %d\n", retval);
		free(thread_ids);
		free(thread_args);
		ebpf_cleanup(interface,true);
		exit(EXIT_FAILURE);
	}
	
	if((retval = ip_llist_init(&banned_list)) < 0){
		fprintf(stderr,"ip_llist_init failed with error code %d\n", retval);
		ip_hashtable_destroy(&htable);
		free(thread_ids);
		free(thread_args);
		ebpf_cleanup(interface,true);
		exit(EXIT_FAILURE);
	}

	if((retval = shmrbuf_init(&rbuf_args, SHMRBUF_READER)) != IO_IPC_SUCCESS){
		if(retval > 0){
            perror("shm_rbuf_init failed");
        }
        else {
            fprintf(stderr,"shm_rbuf_init failed : error code %d\n",retval);
        }
		ip_llist_destroy(&banned_list);
		ip_hashtable_destroy(&htable);
		free(thread_ids);
		free(thread_args);
		ebpf_cleanup(interface,true);
		exit(EXIT_FAILURE);
	}


	if(pthread_create(&thread_ids[0],NULL,unban_thread_routine,&unban_targs)){
		perror("pthread create failed for unban thread");
	} else {

		for(i = 0; i < thread_count; i++){
			thread_args[i].ban_count = 0;
			thread_args[i].ipc_args = &rbuf_args;
			thread_args[i].rcv_count = 0;
			thread_args[i].thread_id = i;
			thread_args[i].wakeup_interval = TIMEOUT;

			if(i > 0){
				if(pthread_create(&thread_ids[i],NULL,ban_thread_routine,&thread_args[i])){
					perror("pthread create failed");
				}
			}

		}

		ban_thread_routine(&thread_args[0]);

		for(i = 0; i < (thread_count); i++){
			if(pthread_join(thread_ids[i], NULL)){
				perror("pthread join failed");
			}
		}

	}

	uint64_t total_rcv_count = 0, total_ban_count = 0;

	for(i = 0; i < thread_count; i++){
		if(thread_args[i].retval != RETURN_SUCC){
			fprintf(stderr,"Watcher thread %d returned with error code %d\n",i,thread_args[i].retval);
		}
		printf("Thread %d : messages received %ld : clients banned %ld\n",i,thread_args[i].rcv_count,thread_args[i].ban_count);
	
		total_rcv_count += thread_args[0].rcv_count;
		total_ban_count += thread_args[0].ban_count;

	}

	if(unban_targs.retval != RETURN_SUCC){
		fprintf(stderr,"Unban thread returned with error code %d\n",thread_args[i].retval);
	}

	printf("Total messages received %ld : total clients banned %ld : total clients unbanned %ld\n",total_rcv_count,total_ban_count,unban_targs.unban_count);

	/*
    if(ebpf_cleanup(interface,true)){
		fprintf(stderr,"ebpf cleanup failed\n");
		ip_llist_destroy(&banned_list);
		ip_hashtable_destroy(&htable);
		free(thread_ids);
		free(thread_args);
		exit(EXIT_FAILURE);
	}
	*/
    
	ip_llist_destroy(&banned_list);
	ip_hashtable_destroy(&htable);

	free(thread_ids);
	free(thread_args);	

}	
