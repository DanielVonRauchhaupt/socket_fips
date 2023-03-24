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
#include <liburing.h>

// Local includes
#include <ip_hashtable.h>
#include <ip_llist.h>
#include <io_ipc.h>
#include <blacklist_common.h>
#include <uring_getline.h>
#include "ip_blacklist.skel.h"

// Default configuration
#define DEFAULT_BAN_TIME 60
#define DEFAULT_BAN_THRESHOLD 1
#define DEFAULT_THREAD_COUNT 4 // For multi-threading
#define DEFAULT_IPC_TYPE DISK
#define DEFAULT_IFACE "enp24s0f0np0"
#define DEFAULT_LOG "udpsvr.log"
#define DEFAULT_MATCH_REGEX "\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} client (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|[a-fA-F0-9:]+) exceeded request rate limit"
#define IP4_REGEX "((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.){3}(25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)"
#define IP6_REGEX "([a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4})|([a-f0-9:]{0,35}::[a-f0-9:]{0,35})"
#define LOGBUF_SIZE 256
#define NTHREADS 1

// Hyperscan
#define MATCH_REGEX_ID 0
#define IP4_REGEX_ID 1
#define IP6_REGEX_ID 2

// Return values
#define RETURN_FAIL (-1)
#define RETURN_SUCC (0)


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
static bool wload_stealing = false;
static char * shm_key = DEFAULT_LOG;
static char * logfile = DEFAULT_LOG;
static char * regex = DEFAULT_MATCH_REGEX;
static char * interface = DEFAULT_IFACE;
static int ipv4_ebpf_map;
static int ipv6_ebpf_map;

// Timeout value for unbanning thread
#define NANOSECONDS_PER_MILLISECOND 1000000
#define TIMEOUT 500 * NANOSECONDS_PER_MILLISECOND

// Structs

// Parameters for unbanning thread
struct unban_targs_t{
	uint32_t wakeup_interval;
	uint64_t unban_count;
	int retval;
};

// Binary ip address representation
union ip_addr_t
{
	uint32_t ipv4;
	__uint128_t ipv6;
};

// Parameters for banning threads
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

	{ "file", 'f', "FILE", OPTION_ARG_OPTIONAL, "Specifies disk as the chosen ipc type", 0},
	{"shm", 's', "KEY", OPTION_ARG_OPTIONAL, "Specifies shared memory as the ipc type", 0},
	{"threads", 't', "N", OPTION_ARG_OPTIONAL, "Specify the number of banning threads to use",0},
	{ "limit", 'l', "N", 0, "Number of matches before a client is banned", 0},
	{ "bantime", 'b', "N", 0, "Number of seconds a client should be banned", 0},
	{ "match", 'm', "REGEX", OPTION_ARG_OPTIONAL, "Use regex matching on logstrings", 0},
	{ "steal", 'w', NULL, 0, "Enable workload stealing for shared memory", 0},
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
	
	case 'f':

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

		if(arg)
		{
			shm_key = arg;
		}

		else 
		{
			shm_key = DEFAULT_LOG;
		}
		

		break;

	case 't':
            if(arg)
			{
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
			}

			else 
			{
				thread_count = DEFAULT_THREAD_COUNT;
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

	case 'w':

			wload_stealing = true;
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
	/**
	*	Description: This this function represents the routine executed
	*   by the unbanning thread. While the global parameter "server_running"
	*   is true, it periodically wakes up and iterates through the banned_list,
	*   to unban clients whos bantime has elapsed.
	*   
	*   Parameters:
	*   	void * args : Pointer to struct unban_targs_t with thread parameters
	*
	*   Returns:
	* 		void * : Pointer to int returncode of the function
	**/


	struct unban_targs_t * targs = (struct unban_targs_t *) args;
	time_t ts;
	struct timespec timeout = {.tv_sec=0,.tv_nsec=targs->wakeup_interval};
	char strerror_buf[64];
	struct ip_listnode_t *iterator, * prev;
	int retval, nr_cpus = libbpf_num_possible_cpus();

	// Blocks (blockable) signals except SIGINT and SIGTERM
	if(block_signals(true))
	{
        error_msg("Failed to block signals\n");
    }
	
	// Registers sig_handler to handle SIGINT and SIGTERM (-> server_running = false)
    if(signal(SIGINT,sig_handler) == SIG_ERR || signal(SIGTERM,sig_handler) == SIG_ERR)
	{
        error_msg("Failed to set signal handler : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
    }

	// Event loop
	while (server_running)
	{

		// Gets current timestap for bantime evaluation
		if((ts = time(NULL)) == -1)
		{
			error_msg("Failed to obtain timestamp : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
			targs->retval = EXIT_FAIL;
			return &targs->retval;
		}

		// Aquires lock for head of the banned_list
		if(pthread_mutex_lock(&banned_list->lock))
		{
			pthread_mutex_unlock(&banned_list->lock);
			error_msg("Failed to claim banned list lock : %s\n",strerror_r(errno,strerror_buf,sizeof(strerror_buf)));
			targs->retval = EXIT_FAIL;
			return &targs->retval;
		}

		// Find first entry in the banned_list whos bantime has elapsed.
		iterator = banned_list->head;

		if(iterator != NULL)
		{
			if((ts - iterator->timestamp) > bantime)
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

					if((ts - iterator->timestamp) > bantime)
					{
						prev->next = NULL;
						break;
					}
					prev = iterator;
					iterator = iterator->next;
				}

			}

			// Unban all clients with an elapsed bantime
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

		// Timeout after checking banned_list
		nanosleep(&timeout,NULL);
	}
	
	targs->retval = EXIT_SUCCESS;
	return &targs->retval;

}
// Todo: Unittest for regex match
int regex_match_handler(unsigned int id, unsigned long long from, unsigned long long to,
                  unsigned int flags, void *ctx)
				  {

	/**
	 *  Description : Handler function that is called if hs_scan finds a match.
	 *  
	 *  Parameters : 
	 * 		unsigned int id : ID of the matched regular expression (see hs_compile)
	 * 		unsigned long long from : Start index of the match
	 * 		unsigned long long to : End index of the match
	 * 		unsigned int flags : Flags set for match
	 *      void *ctx : Context pointer, expects pointer to struct ban_targs_t
	 * 
	 *  Returns : 
	 * 		int : 0, if matching should continue, 1 else.  
	*/

	UNUSED(flags);

	struct ban_targs_t * context = (struct ban_targs_t *)ctx;

	switch (id)
	{
	case MATCH_REGEX_ID:
		context->match = true;
		return (context->domain != -1 ) ? 1 : 0;
	
	case IP4_REGEX_ID:

		from = to;

		// Adjust to and from if not at the end of the address (assumes withespace around address)

		while(to + 1 < LOGBUF_SIZE && context->logmsg_buf[to] != ' ') {to++;}

		while(from > 0 && context->logmsg_buf[from-1] != ' ') {from--;}

		context->logmsg_buf[to] = '\0';

		if (inet_pton(AF_INET,&context->logmsg_buf[from],&context->ip_addr.ipv4) == 1) 
		{
			context->domain = AF_INET;
			context->logmsg_buf[to] = ' ';
			return (context->match) ? 1 : 0;
		}
		context->domain = -1;
		context->logmsg_buf[to] = ' ';
		return 0;

	case IP6_REGEX_ID:

		from = to;

		// Adjust to and from if not at the end of the address (assumes withespace around address)

		while(to + 1 < LOGBUF_SIZE && context->logmsg_buf[to] != ' ') {to++;}

		while(from > 0 && context->logmsg_buf[from-1] != ' ') { from--; }

		context->logmsg_buf[to] = '\0';

		if (inet_pton(AF_INET6, &context->logmsg_buf[from],&context->ip_addr.ipv6) == 1) 
		{
			context->domain = AF_INET6;
			context->logmsg_buf[to+1] = ' ';
			return (context->match) ? 1 : 0;
		}
		context->domain = -1;
		context->logmsg_buf[to+1] = ' ';
		return 0;

	default:
		return 1;
	}

}


void * ban_thread_routine(void * args)
{
	/**
	*	Description: This this function represents the routine executed
	*   by the banning threads. While the global parameter "server_running"
	*   is true, the choosen ipc api is queried for incoming messages. Messages
	*   are then parsed, and identified clients are logged to htable. If the banning 
	*   threshold has been exeeded, the clients ip is added to banned_list and the
	*   corresponding ebpf map.
	*   
	*   Parameters:
	*   	void * args : Pointer to struct ban_targs_t with thread parameters
	*
	*   Returns:
	* 		void * : Pointer to int returncode of the function
	**/

	struct ban_targs_t * targs = (struct ban_targs_t *)args;
	struct shmrbuf_reader_arg_t * shm_arg;
	hs_scratch_t * scratch = NULL; 
	struct timespec tspec = {.tv_sec=0,.tv_nsec=targs->wakeup_interval};
	uint8_t i, seg_index, steal_index, seg_count, steal_count, upper_seg, lower_seg;
	char strerror_buf[64];
	bool read;
	int64_t retval;

	int nr_cpus = libbpf_num_possible_cpus();

	// Communication setup dependant on ipc_type
	switch (ipc_type)
	{
	case DISK:
	
		break;

	case SHM:

		if((targs->logmsg_buf = calloc(sizeof(char),LOGBUF_SIZE)) == NULL)
		{
			error_msg("calloc failed : %s\n",strerror_r(errno, targs->strerror_buf, sizeof(targs->strerror_buf)));
			targs->retval = EXIT_FAIL;
			return &targs->retval;
		}

		shm_arg = (struct shmrbuf_reader_arg_t *) targs->ipc_args;

		if(targs->thread_id > shm_arg->head->segment_count - 1)
		{
			targs->retval = RETURN_SUCC;
			return &targs->retval;
		}

		// Determine the ringbuffer segments for the thread, as well as the range for workload stealing.
		seg_count = shm_arg->head->segment_count / thread_count;

		if((retval = shm_arg->head->segment_count % thread_count) > 0)
		{
			if(retval > targs->thread_id)
			{
				seg_count = seg_count + 1;
				lower_seg = targs->thread_id * seg_count;
			}
			else 
			{
				lower_seg = targs->thread_id * (seg_count + 1);
			}
		}
		else 
		{
			lower_seg = targs->thread_id * seg_count;
		}

		steal_count = (wload_stealing) ? shm_arg->head->segment_count - seg_count : 0;
		upper_seg = lower_seg + seg_count;
		seg_index = lower_seg;
		steal_index = (targs->thread_id) ? 0 : upper_seg;

		break;

	default:
		error_msg("invalid ipc type : %d\n",ipc_type);
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
			if(ipc_type != DISK) {free(targs->logmsg_buf);}
			targs->logmsg_buf = NULL;
			targs->retval = EXIT_FAIL;
			return &targs->retval;
    	}	
	}
    
	// Event loop
	while (server_running)
	{
		read = false;

		// Message receiving dependent on ipc_type
		switch (ipc_type)
		{
		case DISK:
				
			if((retval = uring_getline((struct file_io_t *)targs->ipc_args, &targs->logmsg_buf)) > 0){
				read = true;
				targs->logmsg_buf[retval-1] = '\0';
			}

			break;

		case SHM:

				for(i = 0; i < seg_count; i++)
				{
					// Todo: include workload stealing into shmrbuf api
					if((retval = shmrbuf_read(shm_arg, targs->logmsg_buf, LOGBUF_SIZE, seg_index++)) < 0)
					{
						error_msg("Thread %d : error in shmrbuf_read : segment %d : error code %d\n", targs->thread_id, seg_index - 1, retval);
						if(matching)
							{ hs_free_scratch(scratch); }
						free(targs->logmsg_buf);
						targs->logmsg_buf = NULL;
						targs->retval = EXIT_FAIL;
						return &targs->retval;
					}

					seg_index = (seg_index == upper_seg) ? lower_seg : seg_index;

					if(retval > 0)
					{
						read = true;

						// Remove newline char
						while(--retval > 0)
						{
							if(targs->logmsg_buf[retval] == '\n')
							{
								targs->logmsg_buf[retval] = '\0';
								break;
							}
						}


						break;
					}

				}

				if(read){break;}

				// Steal workload from other threads of own segments are empty 
				// Todo: implement stealing counter
				for(i = 0; i < steal_count; i++)
				{
					if(steal_index >= lower_seg && steal_index < upper_seg)
					{
						steal_index = (upper_seg < shm_arg->head->segment_count) ? upper_seg : 0;
					}

					if((retval = shmrbuf_read(shm_arg, targs->logmsg_buf, sizeof(targs->logmsg_buf), steal_index++)) < 0)
					{
						error_msg("Thread %d : error in shmrbuf_read : segment %d : error code %d\n", targs->thread_id, steal_index - 1, retval);
						if(matching)
							{ hs_free_scratch(scratch); }
						free(targs->logmsg_buf);
						targs->logmsg_buf = NULL;
						targs->retval = EXIT_FAIL;
						return &targs->retval;
					}

					steal_index = (steal_index == shm_arg->head->segment_count) ? 0 : steal_index;

					if(retval > 0)
					{
						read = true;

						// Remove newline char
						while(--retval > 0)
						{
							if(targs->logmsg_buf[retval] == '\n')
							{
								targs->logmsg_buf[retval] = '\0';
								break;
							}
						}

						break;
					}
					
				}

		default:
			break;
		}

		if(read){

			targs->rcv_count++;

			// If matching enabled, matches log message against regex
			if(matching)
			{
				targs->match = false;
				targs->domain = -1;

				if((retval = hs_scan(database, targs->logmsg_buf, LOGBUF_SIZE, 0, scratch, regex_match_handler, targs)) != HS_SUCCESS && retval != HS_SCAN_TERMINATED)
				{
					error_msg("Hyperscan error for logstring %s : error code %d\n",targs->logmsg_buf,retval);
					continue;
				}
				else if(!targs->match || targs->domain == -1)
				{
					continue;
				}
			}

			// Try to convert log message to IP address
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
			
			// Query htable for the number of times an ip address has been logged
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

			// Ban client if ban threshold has been reached
			if(retval == limit)
			{
				time_t ts = time(NULL);

				switch (targs->domain)
				{
				case AF_INET:
					if((retval = ip_llist_push(banned_list, &targs->ip_addr.ipv4, &ts, AF_INET)) < 0)
					{
						error_msg("Error pushing to banned list for logstring : %s : Error Code %d\n",&targs->logmsg_buf,retval);
							continue;
					}
					retval = blacklist_modify(ipv4_ebpf_map, &targs->ip_addr.ipv4, ACTION_ADD, AF_INET, nr_cpus, strerror_buf, sizeof(strerror_buf));
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

		// Timeout, if no messages were read
		else 
		{
			nanosleep(&tspec,NULL);
		}

	}

	if(matching){hs_free_scratch(scratch);}
	if(ipc_type != DISK) {free(targs->logmsg_buf);}
	targs->logmsg_buf = NULL;
	targs->retval = EXIT_SUCCESS;
	return &targs->retval;

}

bool main_cleanup(struct ban_targs_t ** targs, pthread_t ** tids)
{
	/**
	 * Description : Cleans up memory and io channels for the main function
	 * 
	 * Parameters : 
	 * 		 struct ban_targs_t ** targs : Pointer to array of thread argument structs
	 * 	     pthread_t ** tids : Pointer to arry of thread ids
	 * 
	 * Returns : 
	 * 		bool : true, if an error occured, else false
	*/

	int retval;
	bool error = false;

	if(targs != NULL && *targs != NULL && (*targs)[0].ipc_args != NULL)
	{

		switch (ipc_type)
		{
		case DISK:

			io_uring_queue_exit(&((struct file_io_t *)(*targs)[0].ipc_args)->ring);
			
			if(close(((struct file_io_t *)(*targs)[0].ipc_args)->logfile_fd) < 0)
			{
				perror("close");
				error = true;
			}

			free((*targs)[0].ipc_args);

			break;

		case SHM:

			if((retval = shmrbuf_finalize((union shmrbuf_arg_t *)(*targs)[0].ipc_args, SHMRBUF_READER)) != IO_IPC_SUCCESS)
			{
				fprintf(stderr, "shmrbuf_finalize failed with error code: %d\n", retval);
				error = true;
			}

			free((*targs)[0].ipc_args);

			break;
		
		default:
			break;
		}

		free(*targs);
		free(*tids);	
		*targs = NULL;
		*tids = NULL;

	}

	if((retval = ebpf_cleanup(interface,true)) < 0)
	{
		fprintf(stderr,"ebpf cleanup failed : error code %d\n", retval);
		error = true;
	}

	if(banned_list != NULL)
	{
		if((retval = ip_llist_destroy(&banned_list)) != IP_LLIST_SUCCESS)
		{
			fprintf(stderr, "ip_llist_destroy failed with error code %d\n", retval);
			error = true;
		}
	}
	
	if(htable != NULL)
	{
		if((retval = ip_hashtable_destroy(&htable)) < 0)
		{
			fprintf(stderr, "ip_hashtable_destroy failed with error code %d\n", retval);
			error = true;
		}
	}

	if(database != NULL)
	{
		if((retval = hs_free_database(database)) != HS_SUCCESS)
		{
			fprintf(stderr, "hs_free_database failed with error code %d\n", retval);
			error = true;

		}
	}	

	return error;

}


int main(int argc, char **argv)
{
	/**
	 * Description : Main function of the program. Parses commandline arguments, sets up
	 * the ipc api, loads the ebpf program, spawns unbanning and banning threads.
	 * 
	 * 
	*/

	// Avoid unused variable warning
	UNUSED(file_port_blacklist);
	UNUSED(file_port_blacklist_count);
	UNUSED(file_blacklist_ipv6_subnet);
	UNUSED(file_blacklist_ipv6_subnetcache);
	UNUSED(file_verdict);
	
	// Variables
    struct arguments args = {.ipc_set=false};
	struct ban_targs_t * thread_args;
	struct unban_targs_t unban_targs = {.unban_count = 0,.wakeup_interval=TIMEOUT};
	struct file_io_t * file_io_args;
	struct shmrbuf_reader_arg_t * rbuf_arg;
	hs_platform_info_t * platform_info;
	hs_compile_error_t * compile_error;
	pthread_t * thread_ids;
	int retval;
	uint8_t i;

	// Parse commandline arguments
	retval = argp_parse(&argp, argc, argv, 0, NULL, &args);

	if (retval == ARGP_ERR_UNKNOWN)
	{
		exit(EXIT_FAILURE);
	}
		
	if(thread_count > 1 && ipc_type == DISK)
	{
		fprintf(stderr,"No multithreading available for FILE IPC\n");
		thread_count = 1;
	}

	// Setup regex matching, compile chosen regex.
	if (matching) 
	{
		const char * const regexes[] = {regex, IP4_REGEX, IP6_REGEX};
		const unsigned int flags[] = {HS_FLAG_SINGLEMATCH , HS_FLAG_SINGLEMATCH, HS_FLAG_SINGLEMATCH};
		const unsigned int ids[] = {0 , 1, 2};


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

		if(hs_compile_multi(regexes, flags, ids, 3, HS_MODE_BLOCK, platform_info, &database, &compile_error) != HS_SUCCESS)
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

	// Load ebpf program onto chosen interface and setup maps
    if(ebpf_setup(interface,false))
	{
		fprintf(stderr,"ebpf setup failed\n");
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	}

	if((ipv4_ebpf_map = open_bpf_map(file_blacklist_ipv4)) == RETURN_FAIL || (ipv6_ebpf_map = open_bpf_map(file_blacklist_ipv6)) == RETURN_FAIL)
	{
		fprintf(stderr,"ERR: Failed to open bpf map  : %s\n",strerror(errno));
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	}

	// Init memory for thread arguments
	if((thread_ids = (pthread_t *) calloc(sizeof(pthread_t),thread_count)) == NULL ||
	   (thread_args = (struct ban_targs_t *) calloc(sizeof(struct ban_targs_t),thread_count)) == NULL)
	{
		perror("Calloc failed");
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	}

	// Init hashtable for tracking of logged ip addresses
	if((retval = ip_hashtable_init(&htable)) < 0)
	{
		fprintf(stderr,"ip_hashtable_init failed with error code %d\n", retval);
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	}
	
	// Init linked list for tracking of banned ip addresses
	if((retval = ip_llist_init(&banned_list)) < 0)
	{
		fprintf(stderr,"ip_llist_init failed with error code %d\n", retval);
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	}

	// Init ipc communication dependent on chosen ipc_type
	switch (ipc_type)
	{
	case DISK:

		if((file_io_args = (struct file_io_t *) calloc(sizeof(struct file_io_t), 1)) == NULL)
		{
			perror("calloc failed");
		}

		else if((file_io_args->logfile_fd = open(logfile, O_RDONLY, 0644)) == -1)
		{
			perror("open failed");
		}

		else if(io_uring_queue_init(2, &file_io_args->ring, 0) == -1)
		{
			perror("ic_uring_queue_init failed");
		}

		else 
		{
			thread_args[0].ipc_args = (void*) file_io_args;
			break;
		}

		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);

		break;
	
	case SHM:

		if((rbuf_arg = (struct shmrbuf_reader_arg_t *)calloc(sizeof(struct shmrbuf_reader_arg_t),1)) == NULL)
		{
			perror("calloc failed");
			main_cleanup(&thread_args, &thread_ids);
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
			main_cleanup(&thread_args, &thread_ids);
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

	// Create unbanning thread
	if(pthread_create(&thread_ids[0],NULL,unban_thread_routine,&unban_targs))
	{
		perror("pthread create failed for unban thread");
		main_cleanup(&thread_args, &thread_ids);
		exit(EXIT_FAILURE);
	} 
	
	else 
	{
		// Create banning threads
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

		// Start main event loop
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

	// Aggregate and print receive and ban / unban counters.
	for(i = 0; i < thread_count; i++)
	{
		if(thread_args[i].retval != RETURN_SUCC)
		{
			fprintf(stderr,"Watcher thread %d returned with error code %d\n",i,thread_args[i].retval);
		}
		printf("Thread %d : messages received %ld : clients banned %ld\n",i,thread_args[i].rcv_count,thread_args[i].ban_count);
	
		total_rcv_count += thread_args[i].rcv_count;
		total_ban_count += thread_args[i].ban_count;

	}

	if(unban_targs.retval != RETURN_SUCC)
	{
		fprintf(stderr,"Unban thread returned with error code %d\n",thread_args[i].retval);
	}

	printf("Total messages received %ld : total clients banned %ld : total clients unbanned %ld\n",total_rcv_count,total_ban_count,unban_targs.unban_count);

	if(main_cleanup(&thread_args, &thread_ids))
	{
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);

}	
