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
#include <list.h>
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
#include <sys/shm.h>
#include "blacklist_common.h"
#include "ipc.h"
#define RETURN_FAIL (-1)
#define RETURN_SUCC (0)

#define HUGHE_PAGE_SIZE 2048 * 1000

#define SHMKEY "/mnt/scratch/PR/bachelorarbeit/shmkey"

static bool verbose = false;
static pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;

const char *argp_program_version = "ip_blacklist 0.0";
static const char argp_program_doc[] =

"BPF xdp_ddos01 application.\n"
"\n"
"eBPF program is loaded into the kernel and attached at the given device."
"It parses Ethernet packets and drops them in case of finding the source IP"
"address in either an IPv4 or IPv6 blacklist in form of maps or based on the destination"
"port for TCP/UDP  (another map). Blocked addresses are either added by Fail2Ban or another userspace"
"program: ip_blacklist_cmdline. The latter can also be used to add destination ports\n"
"or have a look at packet statistics"
"\n"
"USAGE: ./ip_blacklist [v|d|c] DEVICE\n";
static char args_doc[] = "DEVICE";
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output. Errors will be printed regardless", 0},
	{ "reload", 'r', NULL, 0, "unload eBPF program, clean filesystem and reload program into chosen device",0},
	{ "detach",'d',NULL,0, "detach eBPF program from chosen device",0},
	{ "clean", 'c',NULL,0, "detach eBPF program from chosen device and clean up mounted eBPF file system",0},
	{0},
};
struct arguments
{
  char* device;
  bool verbose;
  //int load;               
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	switch (key) {
	case 'v':
		verbose = 1;
		arguments->verbose = 1;
		break;
	case ARGP_KEY_ARG:
      if (state->arg_num >=2 ){
        /* Too many arguments. */
        fprintf(stderr, "Too many arguments. See usage\n");
		argp_usage (state);
	  	}
		arguments->device = arg;
		break;
	case ARGP_KEY_END:
      if (state->arg_num < 1){
        /* Not enough arguments. */
	    fprintf(stderr, "Not enough arguments. See usage\n");
        argp_usage (state);
        return ARGP_ERR_UNKNOWN;
	  }
	  else{
      break;
	  }
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

int ebpf_cleanup(const char * device,bool unpin,bool verbose){

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

int blacklist_subnet_modify(int fd_cache,int fd_subnetblacklist, char *ip_string, unsigned int action, int nr_cpus, char * strerror_buf, int strerror_size)
{
	__u64 values_prev[nr_cpus];
	__u64 values_next[nr_cpus];
	__u64 value_prev =0;
	__u64 value_next =0;

	if(memset(values_prev, 0,  sizeof(__u64) * nr_cpus) == NULL || memset(values_next, 0,  sizeof(__u64) * nr_cpus) == NULL){
		error_msg("Memset error in blacklist_subnet_modify : Line %d\n",__LINE__);
	}

	__uint128_t key6;
	__u64 subnet_key;

	int res;
	res = inet_pton(AF_INET6, ip_string, &key6);
	if (res <= 0) {
		if (res == 0){
			error_msg(
				"ERR: IPv6 \"%s\" not in presentation format\n",
				ip_string);
		}
		else{
			error_msg("inet_pton : %s\n",strerror_r(errno,strerror_buf,strerror_size));
			return EXIT_FAIL_IP;
		}
	}
	
	subnet_key = (__u64) key6;

	switch (action)
	{
	case ACTION_ADD:
		res = bpf_map_lookup_elem(fd_cache,&subnet_key,&value_prev);
		if (res==-1){
			value_next = 1;
			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_NOEXIST);
			if ( res == -1){
				return map_error(ip_string,subnet_key,strerror_buf,strerror_size);			
			}
		}

		else{
			value_next = value_prev +1;
			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_EXIST);
			if ( res == -1){
				return map_error(ip_string,subnet_key,strerror_buf,strerror_size);			
			}

			if (value_next == SUBNET_THRESHOLD){
				res = bpf_map_update_elem(fd_subnetblacklist,&subnet_key,&values_next,BPF_NOEXIST);
				if ( res == -1){
					map_error(ip_string,subnet_key,strerror_buf,strerror_size);				
				}
			}

		}

		break;

	case ACTION_DEL:

		res = bpf_map_lookup_elem(fd_cache,&subnet_key,&value_prev);
		if ( res == -1){
			return map_error(ip_string,subnet_key,strerror_buf,strerror_size);
		}
		value_next = value_prev -1;
		if (value_next==0){
			res = bpf_map_delete_elem(fd_cache, &subnet_key);
			if ( res == -1){
				return map_error(ip_string,subnet_key,strerror_buf,strerror_size);	
			}
			info_msg("Action del, looking up subnet blacklist  element\n");
			res = bpf_map_lookup_elem(fd_subnetblacklist,&subnet_key,&value_next);
			if(res == 0){ 
				info_msg("Action del, del subnet blacklist  element\n");

				res = bpf_map_delete_elem(fd_subnetblacklist,&subnet_key);
				if ( res == -1){
					return map_error(ip_string,subnet_key,strerror_buf,strerror_size);
				}
			}
		}
		else{
			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_EXIST);
			if ( res == -1){
				return map_error(ip_string,subnet_key,strerror_buf,strerror_size);
			}
		}

		break;
		
	
	default:
		error_msg("ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	 
	if (verbose){
		error_msg(
		"%s() IP:%s key:0x%016llX\n", __func__, ip_string, subnet_key);
		}
	res = bpf_map_lookup_elem(fd_cache, &subnet_key,&value_next);

	info_msg("Values changed to: %llu from %llu\n",value_next, value_prev);
	return EXIT_OK;
}

int blacklist_modify(int fd, char *ip_string, unsigned int action, unsigned int domain,int nr_cpus, char * strerror_buf, int strerror_size)
{
	__u64 values[nr_cpus];
	__u32 key4;
	__uint128_t key6;
	int res;

	if(memset(values, 0, sizeof(__u64) * nr_cpus) == NULL || memset(&key4, 0, sizeof(__u32)) == NULL){
		error_msg("Memset Error in blacklist modify : Line %d\n",__LINE__);
	}

	switch (domain)
	{
	case AF_INET:
		res = inet_pton(AF_INET, ip_string, &key4);
		if (res <= 0) {
			if (res == 0)
				error_msg(
					"ERR: IPv4 \"%s\" not in presentation format\n",
					ip_string);
			else
				error_msg("inet_pton : %s \n",strerror_r(errno,strerror_buf,strerror_size));
			return EXIT_FAIL_IP;
		}
		break;

	case AF_INET6:

		res = inet_pton(AF_INET6, ip_string, &key6);
		if (res <= 0) {
			if (res == 0)
				error_msg(
					"ERR: IPv6 \"%s\" not in presentation format\n",
					ip_string);
			else
				error_msg("inet_pton : %s \n",strerror_r(errno,strerror_buf,strerror_size));
			return EXIT_FAIL_IP;
		}
		break;
	
	default:
		error_msg("Invalid domain : %d\n",domain);
		return EXIT_FAIL_OPTION;
	}

	switch (action)
	{
	case ACTION_ADD:
		if (domain == AF_INET){
		res = bpf_map_update_elem(fd, &key4, values, BPF_NOEXIST);
		}
		else {
		res = bpf_map_update_elem(fd, &key6, values, BPF_NOEXIST);
		}
	break;

	case ACTION_DEL:
		if (domain == AF_INET){
		res = bpf_map_delete_elem(fd, &key4);
		}
		else{
		res = bpf_map_delete_elem(fd, &key6);
		}
	break;

	default:
		error_msg("ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	if (res != 0) { 
		if (domain == AF_INET){
			error_msg(
			"%s() IP:%s key:0x%X errno(%d/%s)",
			__func__, ip_string, key4, errno, strerror_r(errno,strerror_buf,strerror_size));
					}
		else{
			error_msg(
			"%s() IP:%s key:0x%llX%llX errno(%d/%s)",
			__func__, ip_string, (__u64)key6,(__u64)(key6>>64), errno,strerror_r(errno,strerror_buf,strerror_size)); 	
				}
		

		if (errno == 17) {
			#ifndef LONGTERM
			error_msg(": Already in blacklist\n");
			#endif 
			return EXIT_OK;
		}
		error_msg("\n");
		return EXIT_FAIL_MAP_KEY;
	}
	if (verbose){
		if (domain == AF_INET){
				error_msg(
				"%s() IP:%s key:0x%X\n", __func__, ip_string, key4);
		}
		else {
			error_msg(
			"%s() IP:%s key:0x%llX%llX\n", __func__, ip_string, (__u64)key6,(__u64)(key6>>64));
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

    if((bpf_xdp_query_id(ifindex,0,&xdp_fd))!=-1){
        
        ebpf_cleanup(device,false,verbose);
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



int open_bpf_map(const char *file,char * strerror_buf, int strerror_size)
{
	int fd;

	fd = bpf_obj_get(file);
	if (fd < 0) {
		error_msg("ERR: Failed to open bpf map file:%s err(%d):%s\n",
		       file, errno, strerror_r(errno,strerror_buf,strerror_size));
		return RETURN_FAIL;
	}
	return fd;
}







int main(int argc, char **argv){
	
    struct arguments arguments;
	arguments.verbose = 0;
	arguments.device = "";
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, &arguments);
	if (err)
		return err;

    ebpf_setup(arguments.device,true);

	key_t shmkey;
	int shmid;
	void * shm_ptr;
	struct shm_header_t * shm_hdr;
	
	if((shmkey = ftok(SHMKEY,'A')) < 0){
		perror("ftok error");
		ebpf_cleanup(arguments.device,true,true);
		exit(EXIT_FAILURE);
	}

	if((shmid = shmget(shmkey,HUGHE_PAGE_SIZE,IPC_CREAT | SHM_HUGETLB | 0666)) < 0){
		perror("shmget error");
		ebpf_cleanup(arguments.device,true,true);
		exit(EXIT_FAILURE);
	}
	
	if(shm_attach(shmid,&shm_hdr,HUGHE_PAGE_SIZE,true)){
		fprintf(stderr,"Failed to detach shared memory segment\n");
	}

	printf("%p\n",shm_hdr->shm_start);

	if(shm_detach(shm_hdr)){
		fprintf(stderr,"Failed to detach shared memory segment\n");
	}

	if(shmctl(shmid,IPC_RMID,0) < 0 ){
		perror("shmctl error");
		ebpf_cleanup(arguments.device,true,true);
		exit(EXIT_FAILURE);
	}

    ebpf_cleanup(arguments.device,true,true);
    

	


}	
