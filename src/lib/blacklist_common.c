#include "blacklist_common.h"

bool verbose = false;

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
		return EXIT_FAIL;
	}
	if(verbose){printf("Detached eBPF program from device %s.\n",device);}
	
    if(unpin){

        skel = ip_blacklist_bpf__open();
        if (!skel) {
            fprintf(stderr, "Failed to open BPF skeleton\n");
        return EXIT_FAIL;
        }
        err = bpf_object__unpin_maps(skel->obj,NULL);
        if (err) {
            fprintf(stderr, "Failed to unpin maps in /sys/fs/bpf: %s\n",strerror(errno));
        }
        if(verbose){printf("Clean up successful. Maps unlinked.\n");}

    }
    
    return EXIT_OK;
		
}


static int map_error(const char * ip_string, unsigned long long subnet_key,char *strerror_buf, int strerror_size){
	fprintf(stderr,
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
		fprintf(stderr,"Memset error in blacklist_subnet_modify : Line %d\n",__LINE__);
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

			if(verbose){printf("Action del, looking up subnet blacklist  element\n");}

			res = bpf_map_lookup_elem(fd_subnetblacklist,&subnet_key,&value_next);
			if(res == 0){ 

				if(verbose){printf("Action del, del subnet blacklist  element\n");}

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
		fprintf(stderr,"ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	 
	if (verbose){
		
		inet_ntop(AF_INET6,(void *)ip6addr,ip6_str_buf,INET6_ADDRSTRLEN);
		fprintf(stderr,
		"%s() IP:%s key:0x%016llX\n", __func__, ip6_str_buf, subnet_key);
		}
	res = bpf_map_lookup_elem(fd_cache, &subnet_key,&value_next);

	if(verbose){printf("Values changed to: %llu from %llu\n",value_next, value_prev);}

	return EXIT_OK;
}

int blacklist_modify(int fd, void * ip_addr, unsigned int action, unsigned int domain,int nr_cpus, char * strerror_buf, int strerror_size)
{
	__u64 values[nr_cpus];
	int res;
	char ip_str_buf[INET6_ADDRSTRLEN];

	if(memset(values, 0, sizeof(__u64) * nr_cpus) == NULL){
		fprintf(stderr,"Memset Error in blacklist modify : Line %d\n",__LINE__);
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
		fprintf(stderr,"ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	if (res != 0) { 
		if (domain == AF_INET){
			inet_ntop(AF_INET,ip_addr,ip_str_buf,INET6_ADDRSTRLEN);
			if(verbose){fprintf(stderr,
			"%s() line %d IP:%s key:0x%X errno(%d/%s)",
			__func__,__LINE__, ip_str_buf, (__u32)*((__u32 *)ip_addr), errno, strerror_r(errno,strerror_buf,strerror_size));}
					}
		else{
			inet_ntop(AF_INET6,ip_addr,ip_str_buf,INET6_ADDRSTRLEN);
			if(verbose){fprintf(stderr,
			"%s() line %d IP:%s key:0x%llX%llX errno(%d/%s)",
			__func__,__LINE__, ip_str_buf, (__u64)*((__uint128_t *)ip_addr),(__u64)(*((__uint128_t *)ip_addr)>>64), errno,strerror_r(errno,strerror_buf,strerror_size));} 	
				}
		

		if (errno == 17) {
			if(verbose){fprintf(stderr,"address already in blacklist\n");}
			return EXIT_OK;
		}
		fprintf(stderr,"\n");
		return EXIT_FAIL_MAP_KEY;
	}
	if (verbose){
		if (domain == AF_INET){
				inet_ntop(AF_INET,ip_addr,ip_str_buf,INET6_ADDRSTRLEN);
				if(verbose){fprintf(stderr,
				"%s() line %d IP:%s key:0x%X\n", __func__,__LINE__, ip_str_buf, (__u32)*((__u32 *)ip_addr));}
		}
		else {
			inet_ntop(AF_INET6,ip_addr,ip_str_buf,INET6_ADDRSTRLEN);
			if(verbose){fprintf(stderr,
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
		fprintf(stderr,"ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	if (proto == IPPROTO_TCP)
		value = 1 >> DDOS_FILTER_TCP;
	else if (proto == IPPROTO_UDP)
		value = 1 >> DDOS_FILTER_UDP;
	else {
		fprintf(stderr,"ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	if(memset(curr_values, 0, sizeof(__u64) * nr_cpus) == NULL){
		fprintf(stderr,"Memset Error in %s : Line %d\n",__func__,__LINE__);
	}

	if (dport > 65535) {
		fprintf(stderr,
			"ERR: destination port \"%d\" invalid\n",
			dport);
		return EXIT_FAIL_PORT;
	}

	if (bpf_map_lookup_elem(fd, &key, curr_values)) {
		fprintf(stderr,
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
		fprintf(stderr,
			"%s() dport:%d key:0x%X value errno(%d/%s)",
			__func__, dport, key, errno, strerror_r(errno,strerror_buf,strerror_size));

		if (errno == 17) {
			fprintf(stderr,": Port already in blacklist\n");
			return EXIT_OK;
		}
		fprintf(stderr,"\n");
		return EXIT_FAIL_MAP_KEY;
	}

	if (action == ACTION_DEL) {
		/* clear stats on delete */
		if(memset(stat_values, 0, sizeof(__u64) * nr_cpus) == NULL){
			fprintf(stderr,"Memset Error in %s : Line %d\n",__func__,__LINE__);
		}
		res = bpf_map_update_elem(countfd, &key, &stat_values, BPF_EXIST);

		if (res != 0) { /* 0 == success */
			fprintf(stderr,
				"%s() dport:%d key:0x%X value errno(%d/%s)",
				__func__, dport, key, errno, strerror_r(errno,strerror_buf,strerror_size));

			fprintf(stderr,"\n");
			return EXIT_FAIL_MAP_KEY;
		}
	}

	if (verbose)
		fprintf(stderr,
			"%s() dport:%d key:0x%X\n", __func__, dport, key);
	return EXIT_OK;
}

int ebpf_setup(const char * device, bool verbose){

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
                return EXIT_FAIL;
		}
			fprintf(stderr, "Failed to attach eBPF program in xdp skb mode for device: %s. See libbpf error. Exiting.\n",device);
			ip_blacklist_bpf__destroy(skel);
            return EXIT_FAIL;
		}
	if(verbose){printf("Attached program onto device %s in skb mode. Maps pinned to /sys/fs/bpf/.\n",device);}
	return 0;
	}

	if(verbose){printf("Attached program onto device %s in driver mode. Maps pinned to /sys/fs/bpf/	.\n",device);}
	return 0;


}
