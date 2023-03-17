#define _GNU_SOURCE
#include <stdio.h>
#include <sys/shm.h>
#include <io_ipc/shm_ringbuf.h>
#include <time.h>
#include <argp.h>
#include <math.h>

#define MIN(a,b)((a > b) ? b : a)
#define MAX(a,b)((a > b) ? a : b)

const char *argp_program_version = "poll_rbuf 0.0";

static char args_doc[] = "PATH";

static const struct argp_option options[] = {
	{ "interval", 'i', "SECONDS", 0, "Specify interval between buffer state updates"},
	{ "once", 'o', 0, 0, "Display current state of buffer and exit"},
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
  const char * path;
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
		if(state->argc > 4){
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		arguments->path = arg;
		break;
	case ARGP_KEY_END:
		if(arguments->path ==  NULL){
			argp_usage(state);
			return ARGP_ERR_UNKNOWN;
		}
		break;
	default:
		break;
		argp_usage(state);
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

void print_rbuf_info(struct shm_rbuf_arg_t * ipc_arg){
	printf("Ringbuffer at %p\n\n",(void *)ipc_arg);
	printf("Size : %u Bytes\n",ipc_arg->size);
	printf("Segment count %u\n",ipc_arg->segment_count);
}

void print_rbuf_overview(struct shm_rbuf_arg_t * ipc_arg){
	struct shm_rbuf_seg_hdr_t * hdr;
	for(int i = 0; i < ipc_arg->segment_count; i++){
		hdr = ipc_arg->segment_heads[i];
		uint32_t size = hdr->size - sizeof(struct shm_rbuf_seg_hdr_t);
		uint32_t free = size;

		if(hdr->read_index > hdr->write_index){
			free = hdr->read_index - hdr->write_index;
		} else if (hdr->read_index < hdr->write_index) {
			free = size - hdr->write_index + hdr->read_index;
		}
		printf("\n#######################################\n");
		printf("Segment %d at %p\n\n", i, (void*)hdr);
		printf("Size: %u Bytes\n",hdr->size);
		printf("Read index : %d Address: %p\n", hdr->read_index, (void*)((char*)hdr + hdr->read_index + sizeof(struct shm_rbuf_seg_hdr_t)));
		printf("Write index : %d Address: %p\n",hdr->write_index, (void*)((char*)hdr + hdr->write_index + sizeof(struct shm_rbuf_seg_hdr_t)));
		printf("Bytes used: %u\n", size - free);
		printf("Bytes free: %u\n",free);
		printf("Load percentage: %0.2f\n\n",(size-free)/size);

	}
}

int main(int argc, char ** argv){

	int retval;
    struct arguments args = {.path=NULL,.to={.tv_sec=1,.tv_nsec=0},.once=false};
	struct shm_rbuf_arg_t ipc_arg = {.create=false,.key_path=NULL};

	if(argp_parse(&argp,argc,argv,0,NULL,&args)){
		exit(EXIT_FAILURE);
	}

	ipc_arg.key_path = args.path;

	if((retval = shm_rbuf_init(&ipc_arg))){
		fprintf(stderr,"shm_rbuf_init failed with error code %d\n",retval);
		exit(EXIT_FAILURE);
	}

	print_rbuf_info(&ipc_arg);

	if(args.once){

		print_rbuf_overview(&ipc_arg);

	} else {

		while (true)
		{
			print_rbuf_overview(&ipc_arg);
			nanosleep(&args.to,NULL);
		}

	}
	
}