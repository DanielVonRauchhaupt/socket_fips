#define _GNU_SOURCE 1
#include <argp.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <unistd.h>
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
#include <stdlib.h>
#include <fcntl.h>

// Local includes
#include <ip_hashtable.h>
#include <ip_llist.h>
#include <io_ipc.h>
#include <blacklist_common.h>
#include "ip_blacklist.skel.h"

// Default configuration
#define DEFAULT_BAN_TIME 60
#define DEFAULT_BAN_THRESHOLD 1
#define DEFAULT_IPC_TYPE DISK
#define DEFAULT_IFACE "lo"
#define DEFAULT_LOG "udpsvr.log"
#define DEFAULT_MATCH_REGEX "\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} client \\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|[a-fA-F0-9:]+ exceeded request rate limit"
#define IP_REGEX "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|[a-fA-F0-9:]+"
#define LOGBUF_SIZE 256


// Hyperscan
#define MATCH_REGEX_ID 0
#define IP_REGEX_ID 1

// Return values
#define RETURN_FAIL (-1)
#define RETURN_SUCC (0)
#define NTHREADS 1
#define WATCHER_COUNT 1

// Helpers
#define UNUSED(x)(void)(x)

// Open options
#define OPEN_MODE O_RDONLY
#define OPEN_PERM 0644

// global variables
static volatile sig_atomic_t server_running = true;
static pthread_mutex_t stdout_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stderr_lock = PTHREAD_MUTEX_INITIALIZER;
static struct ip_hashtable_t * htable;
static struct ip_llist_t * banned_list; 
static hs_database_t * database;
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

// Parameters fro unbanning thread
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


struct ban_targs_t {
	void * ipc_args;
	uint8_t thread_id;
	uint32_t wakeup_interval;
	uint64_t rcv_count;
	uint64_t ban_count;
	char * logmsg_buf;
	char strerror_buf[64];
	union ip_addr_t ip_addr;
	int8_t domain;
	bool match;
	int retval;
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
	{ "match", 'm', NULL, 0, "Use regex matching on logstrings", 0},
	{ "regex", 'r', "REGEX", 0, "Regular Expression for matching", 0},
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

		if(arguments->ipc_set)
		{
			fprintf(stderr,"Only one IPC type can be specified\n");
			argp_usage(state);
		}

		arguments->ipc_set = true;
		ipc_type = DISK;

		if(arg != NULL)
		{
			logfile = arg;
		}

		break;

	case 's':

		if(arguments->ipc_set)
		{
			fprintf(stderr,"Only one IPC type can be specified\n");
			argp_usage(state);
		}

		arguments->ipc_set = true;
		ipc_type = SHM;

		if(arg == NULL)
		{
			fprintf(stderr,"SHM requires a key parameter\n");
			argp_usage(state);
		}

		shm_key = arg;

		break;

	case 't':
            
            thread_count = (uint8_t) strtol(arg,NULL,10);
            
            if(get_nprocs() < thread_count)
			{
                thread_count = get_nprocs();
                fprintf(stderr,"Using maximum number of banning threads = %d\n",thread_count);
            }

            if(thread_count == 0)
			{
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

			if(arg != NULL)
			{
				regex = arg;
			}

            break;

	case 'm':

			matching = true;
			break;

	case ARGP_KEY_ARG:
      	if (state->arg_num >=2 )
		{
			fprintf(stderr, "Too many arguments. See usage\n");
			argp_usage (state);
	  	}
		
		interface = arg;

		break;
	case ARGP_KEY_END:
      if (state->arg_num < 1)
	  {
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

/* Prints a formatted string to a mutex locked file descriptor */
void sync_message(const char * fmt, pthread_mutex_t * lock, FILE * fp, va_list targs)
{
    pthread_mutex_lock(lock);
    vfprintf(fp, fmt, targs);
    pthread_mutex_unlock(lock);
}

/* Prints a formatted message to stdout (Thread safe) */
void info_msg(const char* fmt,...)
{
    va_list targs;
    va_start(targs, fmt);
    sync_message(fmt,&stdout_lock,stdout,targs);
    va_end(targs);
}

/* Prints a formatted message to stderr (Thread safe) */
void error_msg(const char * fmt,...)
{
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


void sig_handler(int signal)
{
    UNUSED(signal);
    server_running = false;
}


int open_bpf_map(const char *file)
{
	int fd;

	fd = bpf_obj_get(file);
	
	return fd;
}

int8_t block_signals(bool keep)
{
    sigset_t set;
    if(sigfillset(&set))
	{
        return RETURN_FAIL;
    }

    if(keep)
	{
        if(sigdelset(&set,SIGINT) || sigdelset(&set,SIGTERM))
		{
            return RETURN_FAIL;
        }
    }

    if(pthread_sigmask(SIG_BLOCK, &set, NULL))
	{
        return RETURN_FAIL;
    }

    return RETURN_SUCC;
}


void * unban_thread_routine(void * args)
{

	struct unban_targs_t * targs = (struct unban_targs_t *) args;
	time_t ts;
	struct timespec timeout = {.tv_sec=0,.tv_nsec=targs->wakeup_interval};
	char strerror_buf[64];
	struct ip_listnode_t *iterator, * prev;
	int retval, nr_cpus = libbpf_num_possible_cpus();

	if(block_signals(true))
	{
        error_msg("Failed to block signals\n");
    }
	
    if(signal(SIGINT,sig_handler) == SIG_ERR || signal(SIGTERM,sig_handler) == SIG_ERR)
	{
        error_msg("Failed to set signal handler : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
    }

	while (server_running)
	{
		time(&ts);

		if(ts == -1)
		{
			error_msg("Failed to obtain timestamp : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
			targs->retval = EXIT_FAIL;
			return &targs->retval;
		}

		if(pthread_mutex_lock(&banned_list->lock))
		{
			pthread_mutex_unlock(&banned_list->lock);
			error_msg("Failed to claim banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
			targs->retval = EXIT_FAIL;
			return &targs->retval;
		}

		iterator = banned_list->head;

		if(iterator != NULL)
		{
			if((ts - iterator->timestamp) > limit)
			{
				banned_list->head = NULL;
			}
			else 
			{
				prev = iterator;
				iterator = iterator->next;
			}

			if(pthread_mutex_unlock(&banned_list->lock))
			{
				error_msg("Failed to claim banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
				targs->retval = EXIT_FAIL;
				return &targs->retval;
			}

			if(prev != NULL){

				while(iterator != NULL)
				{
					if((ts - iterator->timestamp) > limit)
					{
						prev->next = NULL;
						break;
					}
					prev = iterator;
					iterator = iterator->next;
				}

			}

			while(iterator != NULL)
			{
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

				if(retval < 0)
				{
					error_msg("Error modifying ebf map : error code %d\n",retval);
				} 

				else 
				{
					targs->unban_count++;
				}

				prev = iterator;
				iterator = iterator->next;

				if((retval = ip_hashtable_remove(htable, prev->key, prev->domain)) < 0)
				{
					error_msg("Error removing key from hashtable : error code %d\n",retval);
				}
					
				if((retval = ip_llist_remove(&prev, NULL)) < 0)
				{
					error_msg("Error removing ´ node from banned list : error code %d\n",retval);
				}	

			}
				
		}
		else 
		{
			if(pthread_mutex_unlock(&banned_list->lock))
			{
				error_msg("Failed to claim banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
				targs->retval = EXIT_FAIL;
				return &targs->retval;
			}
		}

		nanosleep(&timeout,NULL);
	}
	
	targs->retval = EXIT_SUCCESS;
	return &targs->retval;

}

int regex_match_handler(unsigned int id, unsigned long long from, unsigned long long to,
                  unsigned int flags, void *ctx)
				  {

	UNUSED(flags);

	struct ban_targs_t * context = (struct ban_targs_t *)ctx;

	if(id == MATCH_REGEX_ID)
	{
		context->match = true;
		return 0;
	}

	if(id == IP_REGEX_ID)
	{
		context->logmsg_buf[to] = '\0';

		if (inet_pton(AF_INET,&context->logmsg_buf[from],&context->ip_addr.ipv4) == 1) 
		{
			context->domain = AF_INET;
			return 1;
		} 
		else if (inet_pton(AF_INET6, &context->logmsg_buf[from],&context->ip_addr.ipv6) == 1) 
		{
			context->domain = AF_INET6;
			return 1;
		} 
		else 
		{
			context->domain = -1;
			return 0;
    	}
	}

	return 0;
}


void * ban_thread_routine(void * args)
{

	struct ban_targs_t * targs = (struct ban_targs_t *)args;
	struct shmrbuf_reader_arg_t * shm_arg;
	hs_scratch_t * scratch = NULL; 
	struct timespec tspec = {.tv_sec=0,.tv_nsec=targs->wakeup_interval};
	uint8_t i, seg_index, steal_index, seg_count, steal_count, upper_seg;
	size_t size = LOGBUF_SIZE - 1;
	ssize_t retval;
	char strerror_buf[64];
	bool read;
	int nr_cpus = libbpf_num_possible_cpus();

	if((targs->logmsg_buf = calloc(sizeof(char),LOGBUF_SIZE)) == NULL)
	{
		error_msg("calloc failed : %s\n",strerror_r(errno, targs->strerror_buf, sizeof(targs->strerror_buf)));
		targs->retval = EXIT_FAIL;
        return &targs->retval;
	}

	switch (ipc_type)
	{
	case DISK:
	
		break;

	case SHM:

		shm_arg = (struct shmrbuf_reader_arg_t *) targs->ipc_args;

		if(targs->thread_id > shm_arg->head->segment_count - 1)
		{
			targs->retval = RETURN_SUCC;
			return &targs->retval;
		}

		seg_count = shm_arg->head->segment_count / thread_count;
		steal_count = shm_arg->head->segment_count - seg_count;
		seg_count = ((shm_arg->head->segment_count % thread_count) < targs->thread_id) ? seg_count + 1 : seg_count;
		upper_seg = targs->thread_id + seg_count;
		seg_index = targs->thread_id;
		steal_index = 0;

		break;

	default:
		error_msg("invalid ipc type : %d\n",ipc_type);
		free(targs->logmsg_buf);
		targs->logmsg_buf = NULL;
		targs->retval = EXIT_FAIL;
        return &targs->retval;
	}

	if(block_signals(false))
	{
        error_msg("failed to block signals\n");
    }

	if(matching)
	{
		if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS)
		{
			error_msg("hyperscan scratch space allocation failed\n");
			free(targs->logmsg_buf);
			targs->logmsg_buf = NULL;
			targs->retval = EXIT_FAIL;
			return &targs->retval;
    	}	
	}
    

	while (server_running)
	{
		read = false;
		targs->match = false;

		switch (ipc_type)
		{
		case DISK:
				
			read = 0 < getline(&targs->logmsg_buf, &size, (FILE *)targs->ipc_args);

			break;

		case SHM:

				for(i = 0; i < seg_count; i++)
				{
					
					if((retval = shmrbuf_read(shm_arg, targs->logmsg_buf, sizeof(targs->logmsg_buf), seg_index++)) < 0)
					{
						error_msg("Thread %d : error in shmrbuf_read : segment %d : error code %d\n");
						if(matching)
							{ hs_free_scratch(scratch); }
						free(targs->logmsg_buf);
						targs->logmsg_buf = NULL;
						targs->retval = EXIT_FAIL;
						return &targs->retval;
					}

					seg_index = (seg_index == upper_seg) ? targs->thread_id : seg_index;

					if(retval > 0)
					{
						read = true;
						break;
					}

				}

				if(read){break;}

				for(i = 0; i < steal_count; i++)
				{
					if(steal_index >= targs->thread_id && steal_index < upper_seg)
					{
						steal_index = (upper_seg < shm_arg->head->segment_count) ? upper_seg : 0;
					}

					if((retval = shmrbuf_read(shm_arg, targs->logmsg_buf, sizeof(targs->logmsg_buf), steal_index++)) < 0)
					{
						error_msg("Thread %d : error in shmrbuf_read : segment %d : error code %d\n");
						if(matching)
							{ hs_free_scratch(scratch); }
						free(targs->logmsg_buf);
						targs->logmsg_buf = NULL;
						targs->retval = EXIT_FAIL;
						return &targs->retval;
					}

					steal_index = (steal_index == shm_arg->head->segment_count) ? 0 : steal_index + 1;

					if(retval > 0)
					{
						read = true;
						break;
					}
					
				}

		default:
			break;
		}

		if(read){

			targs->rcv_count++;

			if(matching)
			{
				if(hs_scan(database, targs->logmsg_buf, LOGBUF_SIZE, 0, scratch, regex_match_handler, targs) != HS_SUCCESS)
				{
					error_msg("Hyperscan error for logstring %s : error code %d\n",targs->logmsg_buf,retval);
					continue;
				}
				else if(!targs->match || targs->domain == -1)
				{
					continue;
				}
			}
			else 
			{
				if (inet_pton(AF_INET, targs->logmsg_buf, &targs->ip_addr.ipv4) == 1) 
				{
					targs->domain = AF_INET;
				} 
				else if (inet_pton(AF_INET6, targs->logmsg_buf, &targs->ip_addr.ipv6) == 1) 
				{
					targs->domain = AF_INET6;
				} 
				else 
				{
					continue;
				}
			}
			
			switch (targs->domain)
			{
			case AF_INET:
					
					retval = ip_hashtable_insert(htable,&targs->ip_addr.ipv4,AF_INET);

					break;

				case AF_INET6:

					retval = ip_hashtable_insert(htable,&targs->ip_addr.ipv6,AF_INET6);

					break;
			
				default:
					continue;
				}

				if(retval < 1)
				{
					error_msg("Error in htable query for logstring : %s : Error Code %d\n",targs->logmsg_buf,retval);
					continue;
				}

				if(retval == limit)
				{
					time_t ts = time(NULL);

					switch (targs->domain)
					{
					case AF_INET:
						if((retval = ip_llist_push(banned_list, &targs->ip_addr.ipv6, &ts, AF_INET)) < 0)
						{
							error_msg("Error pushing to banned list for logstring : %s : Error Code %d\n",&targs->logmsg_buf,retval);
								continue;
						}
					    retval = blacklist_modify(ipv4_ebpf_map, &targs->ip_addr.ipv6, ACTION_ADD, AF_INET, nr_cpus, strerror_buf, sizeof(strerror_buf));
						break;
					
					case AF_INET6:
						if((retval = ip_llist_push(banned_list, &targs->ip_addr.ipv6, &ts, AF_INET6)) < 0)
						{
							error_msg("Error pushing to banned list for logstring : %s : Error Code %d\n",&targs->logmsg_buf,retval);
								continue;
						}
					    retval = blacklist_modify(ipv6_ebpf_map,&targs->ip_addr.ipv6,ACTION_ADD,AF_INET6,nr_cpus,strerror_buf,sizeof(strerror_buf));
						break;

					default:
						continue;
					}

					if(retval != EXIT_OK)
					{
						error_msg("Error modifying blacklist : Error code %d\n",retval);
						continue;
					}

					targs->ban_count++;
				
				} 

		}

		else 
		{
			nanosleep(&tspec,NULL);
		}

	}

	hs_free_scratch(scratch);
	free(targs->logmsg_buf);
	targs->logmsg_buf = NULL;
	targs->retval = EXIT_SUCCESS;
	return &targs->retval;

}

int ipc_cleanup(struct ban_targs_t * targs, uint8_t thread_count, enum ipc_type_t ipc_type)
{
	UNUSED(thread_count);

	int retval = IO_IPC_NULLPTR_ERR;

	switch (ipc_type)
	{
	case DISK:
		
		if(targs != NULL && targs[0].ipc_args != NULL)
		{
			retval = fclose(targs[0].ipc_args);
		}

		break;

	case SHM:

		if(targs != NULL && targs[0].ipc_args != NULL)
		{
			retval = shmrbuf_finalize((union shmrbuf_arg_t *)targs[0].ipc_args, SHMRBUF_READER);
			free(targs[0].ipc_args);
		}

		break;
	
	default:
		return IO_IPC_ARG_ERR;
	}

	return retval;

}


int main(int argc, char **argv)
{

	UNUSED(file_port_blacklist);
	UNUSED(file_port_blacklist_count);
	UNUSED(file_blacklist_ipv6_subnet);
	UNUSED(file_blacklist_ipv6_subnetcache);
	UNUSED(file_verdict);
	
    struct arguments args;
	struct ban_targs_t * thread_args;
	struct unban_targs_t unban_targs = {.unban_count = 0,.wakeup_interval=TIMEOUT};
	struct shmrbuf_reader_arg_t * rbuf_arg;
	hs_platform_info_t * platform_info;
	hs_compile_error_t * compile_error;
	pthread_t * thread_ids;
	int retval;
	uint8_t i;
	retval = argp_parse(&argp, argc, argv, 0, NULL, &args);

	if (retval == ARGP_ERR_UNKNOWN)
	{
		return retval;
	}
		
	if(thread_count > 1 && ipc_type == DISK)
	{
		fprintf(stderr,"No multithreading available for DISK IPC\n");
		thread_count = 1;
	}

	if (matching) 
	{
		const char * const regexes[] = {regex, IP_REGEX};
		const unsigned int flags[] = {HS_FLAG_SINGLEMATCH , HS_FLAG_SOM_LEFTMOST};
		const unsigned int ids[] = {0 , 1};


		if((platform_info = (hs_platform_info_t *) calloc(sizeof(hs_platform_info_t), 1)) == NULL)
		{
			perror("calloc failed");
		}

		else if(hs_populate_platform(platform_info) != HS_SUCCESS)
		{
			fprintf(stderr, "hs_populate_platform failed\n");
			free(platform_info);
			platform_info = NULL;
		}

		if(hs_compile_multi(regexes, flags, ids, 2, HS_MODE_BLOCK, platform_info, &database, &compile_error) != HS_SUCCESS)
		{
			fprintf(stderr,"Hyperscan compilation failed with error code %d, %s\n", compile_error->expression, compile_error->message);
			hs_free_compile_error(compile_error);
			exit(EXIT_FAILURE);
		}

		if(platform_info != NULL)
		{
			free(platform_info);
			platform_info = NULL;
		}
    } 

    if(ebpf_setup(interface,false))
	{
		fprintf(stderr,"ebpf setup failed\n");
		exit(EXIT_FAILURE);
	}

	if((ipv4_ebpf_map = open_bpf_map(file_blacklist_ipv4)) == RETURN_FAIL || (ipv6_ebpf_map = open_bpf_map(file_blacklist_ipv6)) == RETURN_FAIL)
	{
		fprintf(stderr,"ERR: Failed to open bpf map  : %s\n",strerror(errno));
		ebpf_cleanup(interface,true);
		exit(EXIT_FAILURE);
	}

	if((thread_ids = (pthread_t *) calloc(sizeof(pthread_t),thread_count)) == NULL ||
	   (thread_args = (struct ban_targs_t *) calloc(sizeof(struct ban_targs_t),thread_count)) == NULL)
	{
		perror("Calloc failed");
		hs_free_database(database);
		ebpf_cleanup(interface,true);
		exit(EXIT_FAILURE);
	}

	if((retval = ip_hashtable_init(&htable)) < 0)
	{
		fprintf(stderr,"ip_hashtable_init failed with error code %d\n", retval);
		free(thread_ids);
		free(thread_args);
		hs_free_database(database);
		ebpf_cleanup(interface,true);
		exit(EXIT_FAILURE);
	}
	
	if((retval = ip_llist_init(&banned_list)) < 0)
	{
		fprintf(stderr,"ip_llist_init failed with error code %d\n", retval);
		ip_hashtable_destroy(&htable);
		free(thread_ids);
		free(thread_args);
		hs_free_database(database);
		ebpf_cleanup(interface,true);
		exit(EXIT_FAILURE);
	}

	switch (ipc_type)
	{
	case DISK:
		
		if((thread_args[0].ipc_args = fopen(logfile,"r")) == NULL)
		{
			perror("fopen failed for logfile");
			ip_hashtable_destroy(&htable);
			ip_llist_destroy(&banned_list);
			free(thread_ids);
			free(thread_args);
			hs_free_database(database);
			ebpf_cleanup(interface,true);
			exit(EXIT_FAILURE);
		}

		break;
	
	case SHM:

		if((rbuf_arg = (struct shmrbuf_reader_arg_t *)calloc(sizeof(struct shmrbuf_reader_arg_t),1)) == NULL)
		{
			perror("calloc failed");
			ip_llist_destroy(&banned_list);
			ip_hashtable_destroy(&htable);
			free(thread_ids);
			free(thread_args);
			hs_free_database(database);
			ebpf_cleanup(interface,true);
			exit(EXIT_FAILURE);
		}

		rbuf_arg->shm_key = shm_key;

		if((retval = shmrbuf_init((union shmrbuf_arg_t *)rbuf_arg, SHMRBUF_READER)) != IO_IPC_SUCCESS)
		{
			if(retval > 0)
			{
				perror("shm_rbuf_init failed");
			}
			else {
				fprintf(stderr,"shm_rbuf_init failed : error code %d\n",retval);
			}
			ip_llist_destroy(&banned_list);
			ip_hashtable_destroy(&htable);
			free(rbuf_arg);
			free(thread_ids);
			free(thread_args);
			hs_free_database(database);
			ebpf_cleanup(interface,true);
			exit(EXIT_FAILURE);
		}

		for(i = 0; i < thread_count; i++)
		{
			thread_args[i].ipc_args = (void*) rbuf_arg;
		}

		break;

	default:
		break;
	}

	if(pthread_create(&thread_ids[0],NULL,unban_thread_routine,&unban_targs))
	{
		perror("pthread create failed for unban thread");
		ipc_cleanup(thread_args, thread_count, ipc_type);
		ip_hashtable_destroy(&htable);
		ip_llist_destroy(&banned_list);
		free(thread_args);
		free(thread_ids);
		hs_free_database(database);
		ebpf_cleanup(interface, true);
		exit(EXIT_FAILURE);
	} 
	
	else 
	{

		for(i = 0; i < thread_count; i++)
		{
			thread_args[i].ban_count = 0;
			thread_args[i].rcv_count = 0;
			thread_args[i].thread_id = i;
			thread_args[i].wakeup_interval = TIMEOUT;

			if(i > 0)
			{
				if(pthread_create(&thread_ids[i],NULL,ban_thread_routine,&thread_args[i]))
				{
					perror("pthread create failed");
				}
			}

		}

		ban_thread_routine(&thread_args[0]);

		for(i = 0; i < thread_count; i++)
		{
			if(pthread_join(thread_ids[i], NULL))
			{
				perror("pthread join failed");
			}
		}

	}

	uint64_t total_rcv_count = 0, total_ban_count = 0;

	printf("\n");

	for(i = 0; i < thread_count; i++)
	{
		if(thread_args[i].retval != RETURN_SUCC)
		{
			fprintf(stderr,"Watcher thread %d returned with error code %d\n",i,thread_args[i].retval);
		}
		printf("Thread %d : messages received %ld : clients banned %ld\n",i,thread_args[i].rcv_count,thread_args[i].ban_count);
	
		total_rcv_count += thread_args[0].rcv_count;
		total_ban_count += thread_args[0].ban_count;

	}

	if(unban_targs.retval != RETURN_SUCC)
	{
		fprintf(stderr,"Unban thread returned with error code %d\n",thread_args[i].retval);
	}

	printf("Total messages received %ld : total clients banned %ld : total clients unbanned %ld\n",total_rcv_count,total_ban_count,unban_targs.unban_count);

    if((retval = ebpf_cleanup(interface,true)) < 0)
	{
		fprintf(stderr,"ebpf cleanup failed : error code %d\n", retval);
	}
    
	if((retval = ipc_cleanup(thread_args, thread_count, ipc_type)) != IO_IPC_SUCCESS)
	{
		fprintf(stderr,"ipc_cleanup failed with error code : %d\n", retval);
	}
	
	if((retval = ip_llist_destroy(&banned_list)) != IP_LLIST_SUCCESS)
	{
		fprintf(stderr, "ip_llist_destroy failed with error code %d\n", retval);
	}

	if((retval = ip_hashtable_destroy(&htable)) != IP_HTABLE_SUCCESS)
	{
		fprintf(stderr, "ip_hashtable_destroy failed with error code %d\n", retval);
	}

	if((retval = hs_free_database(database)) != HS_SUCCESS)
	{
		fprintf(stderr, "hs_free_database failed with error code %d\n", retval);
	}

	free(thread_ids);
	free(thread_args);	

}	
