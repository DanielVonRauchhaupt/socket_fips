#define _GNU_SOURCE
#include <stdio.h>
#include <sys/shm.h>
#include <shm_ringbuf.h>
#include <time.h>
#include <argp.h>
#include <math.h>

#define MIN(a,b)((a > b) ? b : a)
#define MAX(a,b)((a > b) ? a : b)

#define DEFAULT_KEY "udpsvr.log"

const char *argp_program_version = "poll_rbuf 0.0";

static char args_doc[] = "PATH";

static const struct argp_option options[] = {
	{ "interval", 'i', "SECONDS", 0, "Specify interval between buffer state updates", 0},
	{ "once", 'o', 0, 0, "Display current state of buffer and exit", 0},
    {0}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state);

static const struct argp argp = {
	.options = options,
	.parser = parse_arg,
	.args_doc = args_doc,
	.doc = "Documentation"
};

struct arguments
{
  char * path;
  struct timespec to;
  bool once;
            
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	unsigned int milliseconds;

	switch (key) {
	case 'i':
		milliseconds = MIN(10000,MAX((int)(strtod(arg,NULL) * 1000),10));
		arguments->to.tv_sec = (int)(milliseconds / 1000);
		arguments->to.tv_nsec = milliseconds % 1000;
		break;
	case 'o':
      arguments->once = true;
	  break;
	case ARGP_KEY_ARG:
		if(state->arg_num == 0)
		{
			arguments->path = arg;
		}
		else 
		{
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case ARGP_KEY_END:
		if(arguments->path ==  NULL)
		{
			arguments->path = DEFAULT_KEY;
		}
		break;
	default:
		break;
		argp_usage(state);
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

void print_rbuf_info(struct shmrbuf_reader_arg_t * rbuf_arg)
{
	printf("\n#######################################\n");
	printf("Ringbuffer at %p\n\n",(void *)rbuf_arg->head);
	printf("Number of segments : %d\n",rbuf_arg->head->segment_count);
	printf("Number of lines per segment : %u\n",rbuf_arg->head->lines);
	printf("Line size : %u Bytes\n",rbuf_arg->head->line_size);
	printf("Total buffer size : %u Bytes\n",rbuf_arg->head->lines * rbuf_arg->head->line_size * rbuf_arg->head->segment_count);
	printf("Number of readers : %d\n",rbuf_arg->head->reader_count);
	printf("Overwrite : %s\n",(rbuf_arg->head->overwrite) ? "true" : "false");
}

void print_rbuf_overview(struct shmrbuf_reader_arg_t * rbuf_arg)
{
	struct shmrbuf_seg_rhdr_t * hdr;
	uint64_t total_free = 0, total_used = 0;
	for(int i = 0; i < rbuf_arg->head->segment_count; i++){
		hdr = &rbuf_arg->segment_hdrs[i];

		atomic_uint_fast32_t * reader;
		uint64_t mdist = 0, dst;

		printf("\n#######################################\n");
		printf("Segment %d at %p\n\n", i, (void*)hdr->write_index);
		printf("Writer at line %ld, address %p\n",*hdr->write_index, (char *)hdr->data + rbuf_arg->head->line_size * (*hdr->write_index));

		for(int i = 0; i < rbuf_arg->head->reader_count; i++)
		{
			reader = hdr->write_index + (i + 1);
			dst = (*reader <= *hdr->write_index) ? (*hdr->write_index - *reader) : (rbuf_arg->head->lines - (*reader - *hdr->write_index));
			mdist = (dst > mdist) ? dst : mdist;

			printf("Reader %d at line %ld, address %p\n", i,  *reader, (char *)hdr->data + rbuf_arg->head->line_size * (*reader));
		}

		total_free += rbuf_arg->head->lines - mdist - 1;
		total_used += mdist + 1;

		printf("Lines total: %u\n", rbuf_arg->head->lines);
		printf("Lines used: %lu\n", mdist + 1);
		printf("Lines free: %lu\n",rbuf_arg->head->lines - mdist - 1);
		printf("Load percentage: %0.2f\n\n",((mdist + 1) /  (double) rbuf_arg->head->lines) * 100);

	}

	printf("\n#######################################\n");
	printf("Total\n\n");
	printf("Lines total: %u\n", rbuf_arg->head->lines * rbuf_arg->head->segment_count);
	printf("Lines used: %lu\n", total_used);
	printf("Lines free: %lu\n",total_free);
	printf("Load percentage: %0.2f\n\n",((total_used) /  (double) (rbuf_arg->head->lines * rbuf_arg->head->segment_count)) * 100);

}

int main(int argc, char ** argv){

	int retval;
    struct arguments args = {.path=NULL,.to={.tv_sec=1,.tv_nsec=0},.once=false};
	struct shmrbuf_reader_arg_t rbuf_arg = {.shm_key=DEFAULT_KEY, .no_reg=true};

	if(argp_parse(&argp,argc,argv,0,NULL,&args)){
		exit(EXIT_FAILURE);
	}

	rbuf_arg.shm_key = args.path;

	if((retval = shmrbuf_init((union shmrbuf_arg_t *)&rbuf_arg, SHMRBUF_READER))){
		fprintf(stderr,"shm_rbuf_init failed with error code %d\n",retval);
		exit(EXIT_FAILURE);
	}

	print_rbuf_info(&rbuf_arg);

	if(args.once){

		print_rbuf_overview(&rbuf_arg);

	} else {

		while (true)
		{
			print_rbuf_overview(&rbuf_arg);
			nanosleep(&args.to,NULL);
		}

	}
	
}