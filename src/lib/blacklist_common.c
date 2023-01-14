#define _GNU_SOURCE 1
#include "include/blacklist_common.h"

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

static int blacklist_modify(int fd, char *ip_string, unsigned int action, unsigned int iptype)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 values[nr_cpus];
	__u32 key4;
	unsigned __int128 key6;
	int res;
	//printf("IP type is: %d\n",iptype);
	memset(values, 0, sizeof(__u64) * nr_cpus);
	if (iptype == 4){
		/* Convert IP-string into 32-bit network byte-order value */
		res = inet_pton(AF_INET, ip_string, &key4);
		if (res <= 0) {
			if (res == 0)
				fprintf(stderr,
					"ERR: IPv4 \"%s\" not in presentation format\n",
					ip_string);
			else
				perror("inet_pton");
			return EXIT_FAIL_IP;
		}
	}
	else if (iptype == 6){
		/* Convert IP-string into 128-bit network byte-order value */
		res = inet_pton(AF_INET6, ip_string, &key6);
		if (res <= 0) {
			if (res == 0)
				fprintf(stderr,
					"ERR: IPv6 \"%s\" not in presentation format\n",
					ip_string);
			else
				perror("inet_pton");
			return EXIT_FAIL_IP;
		}
	}
	//printf("Key is: %llX%llX\n",(__u64)key6,(__u64)(key6>>64));

	if (action == ACTION_ADD) {
		if (iptype == 4){
		res = bpf_map_update_elem(fd, &key4, values, BPF_NOEXIST);
		}
		else if (iptype == 6){
		res = bpf_map_update_elem(fd, &key6, values, BPF_NOEXIST);
		}
	} else if (action == ACTION_DEL) {
		if (iptype == 4){
		res = bpf_map_delete_elem(fd, &key4);
		}
		else if (iptype == 6){

		res = bpf_map_delete_elem(fd, &key6);
		}
	} else {
		fprintf(stderr, "ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	if (res != 0) { /* 0 == success */
		if (iptype == 4){
			fprintf(stderr,
			"%s() IP:%s key:0x%X errno(%d/%s)",
			__func__, ip_string, key4, errno, strerror(errno));
					}
		else if (iptype == 6){
			fprintf(stderr,
			"%s() IP:%s key:0x%llX%llX errno(%d)",
			__func__, ip_string, (__u64)key6,(__u64)(key6>>64), errno); //strerror(errno));	
				}
		

		if (errno == 17) {
			#ifndef LONGTERM
			fprintf(stderr, ": Already in blacklist\n");
			#endif 
			return EXIT_OK;
		}
		fprintf(stderr, "\n");
		return EXIT_FAIL_MAP_KEY;
	}
	if (verbose){
		if (iptype == 4){
				fprintf(stderr,
				"%s() IP:%s key:0x%X\n", __func__, ip_string, key4);
		}
		else if (iptype == 6){
			fprintf(stderr,
			"%s() IP:%s key:0x%llX%llX\n", __func__, ip_string, (__u64)key6,(__u64)(key6>>64));
			}
	}	
	return EXIT_OK;
}

static int blacklist_port_modify(int fd, int countfd, int dport, unsigned int action, int proto)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 curr_values[nr_cpus];
	__u64 stat_values[nr_cpus];
	__u64 value;
	__u32 key = dport;
	int res; 
	int i;

	if (action != ACTION_ADD && action != ACTION_DEL)
	{
		fprintf(stderr, "ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	if (proto == IPPROTO_TCP)
		value = 1 >> DDOS_FILTER_TCP;
	else if (proto == IPPROTO_UDP)
		value = 1 >> DDOS_FILTER_UDP;
	else {
		fprintf(stderr, "ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}

	memset(curr_values, 0, sizeof(__u64) * nr_cpus);

	if (dport > 65535) {
		fprintf(stderr,
			"ERR: destination port \"%d\" invalid\n",
			dport);
		return EXIT_FAIL_PORT;
	}

	if (bpf_map_lookup_elem(fd, &key, curr_values)) {
		fprintf(stderr,
			"%s() 1 bpf_map_lookup_elem(key:0x%X) failed errno(%d/%s)",
			__func__, key, errno, strerror(errno));
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
			__func__, dport, key, errno, strerror(errno));

		if (errno == 17) {
			fprintf(stderr, ": Port already in blacklist\n");
			return EXIT_OK;
		}
		fprintf(stderr, "\n");
		return EXIT_FAIL_MAP_KEY;
	}

	if (action == ACTION_DEL) {
		/* clear stats on delete */
		memset(stat_values, 0, sizeof(__u64) * nr_cpus);
		res = bpf_map_update_elem(countfd, &key, &stat_values, BPF_EXIST);

		if (res != 0) { /* 0 == success */
			fprintf(stderr,
				"%s() dport:%d key:0x%X value errno(%d/%s)",
				__func__, dport, key, errno, strerror(errno));

			fprintf(stderr, "\n");
			return EXIT_FAIL_MAP_KEY;
		}
	}

	if (verbose)
		fprintf(stderr,
			"%s() dport:%d key:0x%X\n", __func__, dport, key);
	return EXIT_OK;
}

/*
static int blacklist_subnet_modify(int fd, char *ip_string, unsigned int action)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 values_prev[nr_cpus];
	__u64 values_next[nr_cpus];
	__u64 value_prev =0;
	__u64 value =0;
				memset(values_prev, 0,  sizeof(__u64) * nr_cpus);
				memset(values_next, 0,  sizeof(__u64) * nr_cpus);



	unsigned __int128 key6;
	__u64 subnet_key;
	int res;
	res = inet_pton(AF_INET6, ip_string, &key6);
	if (res <= 0) {
		if (res == 0){
			fprintf(stderr,
				"ERR: IPv6 \"%s\" not in presentation format\n",
				ip_string);
		}
		else{
			perror("inet_pton");
		return EXIT_FAIL_IP;
		}
	}
	
	subnet_key = (__u64) key6;
	printf("IP:%s key:0x%016llX%016llX, subnet_key: 0x%016llX\n",
			ip_string, (__u64)key6,(__u64)(key6>>64),subnet_key);


	if (action == ACTION_ADD) {

		//printf("Action add\n");
		res = bpf_map_lookup_elem(fd,&subnet_key,values_prev);
		//printf("res: %d\n",res);
		if (res==-1){
			//value = 1;
			for (int i = 0; i < nr_cpus; i++){
				values_next[i] = 1;
			}
			//memset(values_next, 1,  sizeof(__u64) * nr_cpus);
			res = bpf_map_update_elem(fd, &subnet_key, &values_next, BPF_NOEXIST);
			//printf("Action add, creating element\n");

		}
		else{
			//value = values_prev[0] + 1;
			for (int i = 0; i < nr_cpus; i++){
				values_next[i] = values_prev[i]+1;
			}
			res = bpf_map_update_elem(fd, &subnet_key, &values_next, BPF_EXIST);
			//printf("Action add, updating element\n");

		}
	} else if (action == ACTION_DEL) {
		res = bpf_map_lookup_elem(fd,&subnet_key,values_prev);
		//printf("values_prev: %llu\n",value);
		//value = values_prev[0]-1;
		for (int i = 0; i < nr_cpus; i++){
			values_next[i] = values_prev[i]-1;
		}

		if (values_next[0]==0){
			res = bpf_map_delete_elem(fd, &subnet_key);
			//printf("Action del, del element\n");

		}
		else{
			//memset(values_next, value,  sizeof(__u64) * nr_cpus);
			res = bpf_map_update_elem(fd, &subnet_key, &values_next, BPF_EXIST);
			//printf("Action del, updating element\n");

		}
	}
	 else {
		fprintf(stderr, "ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}
	 
	if (res != 0) { 
		fprintf(stderr,
			"%s() IP:%s key:0x%016llX errno(%d)\n",
			__func__, ip_string,subnet_key, errno); //strerror(errno));	
		return EXIT_FAIL_MAP_KEY;
		}

	if (verbose){
		fprintf(stderr,
		"%s() IP:%s key:0x%016llX\n", __func__, ip_string, subnet_key);
		}
	return EXIT_OK;
}
*/

static int blacklist_subnet_modify(int fd_cache,int fd_subnetblacklist, char *ip_string, unsigned int action)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 values_prev[nr_cpus];
	__u64 values_next[nr_cpus];
	__u64 value_prev =0;
	__u64 value_next =0;
				memset(values_prev, 0,  sizeof(__u64) * nr_cpus);
				memset(values_next, 0,  sizeof(__u64) * nr_cpus);



	unsigned __int128 key6;
	__u64 subnet_key;
	int res;
	res = inet_pton(AF_INET6, ip_string, &key6);
	if (res <= 0) {
		if (res == 0){
			fprintf(stderr,
				"ERR: IPv6 \"%s\" not in presentation format\n",
				ip_string);
		}
		else{
			perror("inet_pton");
			return EXIT_FAIL_IP;
		}
	}
	
	subnet_key = (__u64) key6;
	//printf("IP:%s key:0x%016llX%016llX, subnet_key: 0x%016llX\n",
	//		ip_string, (__u64)key6,(__u64)(key6>>64),subnet_key);


	if (action == ACTION_ADD) {

		//printf("Action add\n");
		res = bpf_map_lookup_elem(fd_cache,&subnet_key,&value_prev);
		//printf("res: %d\n",res);
		if (res==-1){
			value_next = 1;
			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_NOEXIST);
			//printf("Action add, creating cache element\n");
			if ( res == -1){
				goto map_error;			
			}
		}
		else{
			//value = values_prev[0] + 1;
			value_next = value_prev +1;
			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_EXIST);
			if ( res == -1){
				goto map_error;			
			}
			//printf("Action add, updating element\n");
			if (value_next == SUBNET_THRESHOLD){
				res = bpf_map_update_elem(fd_subnetblacklist,&subnet_key,&values_next,BPF_NOEXIST);
				if ( res == -1){
					goto map_error;				
				}
			}

		}
	} 
	else if (action == ACTION_DEL) {
		res = bpf_map_lookup_elem(fd_cache,&subnet_key,&value_prev);
		if ( res == -1){
			goto map_error;
		}
		value_next = value_prev -1;
		if (value_next==0){
			res = bpf_map_delete_elem(fd_cache, &subnet_key);
			if ( res == -1){
				goto map_error;			
			}
			printf("Action del, looking up subnet blacklist  element\n");
			res = bpf_map_lookup_elem(fd_subnetblacklist,&subnet_key,&value_next);
			if (res == -1){
			// nothing to do;
			
			}
			if(res == 0){ 
				printf("Action del, del subnet blacklist  element\n");

				res = bpf_map_delete_elem(fd_subnetblacklist,&subnet_key);
				if ( res == -1){
					goto map_error;
				}
			}
		}
		else{
			//memset(values_next, value,  sizeof(__u64) * nr_cpus);
			res = bpf_map_update_elem(fd_cache, &subnet_key, &value_next, BPF_EXIST);
			//printf("Action del, updating element\n");
			if ( res == -1){
				goto map_error;
			}
		}
	}
	else {
		fprintf(stderr, "ERR: %s() invalid action 0x%x\n",
			__func__, action);
		return EXIT_FAIL_OPTION;
	}
	 
	if (verbose){
		fprintf(stderr,
		"%s() IP:%s key:0x%016llX\n", __func__, ip_string, subnet_key);
		}
	res = bpf_map_lookup_elem(fd_cache, &subnet_key,&value_next);

	printf("Values changed to: %llu from %llu\n",value_next, value_prev);
	return EXIT_OK;

map_error:
	fprintf(stderr,
			"%s() IP:%s key:0x%016llX errno(%d)\n",
			__func__, ip_string,subnet_key, errno); //strerror(errno));	
	return EXIT_FAIL_MAP_KEY;
}