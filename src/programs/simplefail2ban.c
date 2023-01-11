
#include <linux/if_link.h>
#include <getopt.h>

#include <hs.h>
#include <libbpf.h>
#include <xdp_ddos01_blacklist.skel.h>
#include <xdp_ddos01_blacklist_common.h>

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"add",		no_argument,		NULL, 'a' },
	{"del",		no_argument,		NULL, 'd' },
	{"ip",		required_argument,	NULL, 'i' },
	{"stats",	no_argument,		NULL, 's' },
	{"sec",		required_argument,	NULL, 's' },
	{"list",	no_argument,		NULL, 'l' },
	{"udp-dport",	required_argument,	NULL, 'u' },
	{"tcp-dport",	required_argument,	NULL, 't' },
	{0, 0, NULL,  0 }
};



int main(int argc, char * argv[]){



}