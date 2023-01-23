#define _GNU_SOURCE 1
#include "blacklist_common.h"


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

	unsigned __int128 key6;
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
		error_msg(stderr,
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
	unsigned __int128 key6;
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
			error_msg(stderr, ": Already in blacklist\n");
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
		error_msg(stderr,
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