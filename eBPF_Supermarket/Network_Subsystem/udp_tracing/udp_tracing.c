#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "udp_tracing.h"
#include "udp_tracing.skel.h"

static volatile bool exiting = false;

int count = 0;
int count_i = 0;
bool verbose = false;

int sport,dport,sampling,local;

const char argp_program_doc[] = "Trace time delay in network subsystem \n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "sport", 's', "SPORT", 0, "trace this source port only" },
    { "dport", 'd', "DPORT", 0, "trace this destination port only" },
	{ "count", 'c', "COUNT", 0, "count of outputs"},
	{ "local", 'l', "LOCAL", 0, "show local connections"},

	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{   
    char *end;
    switch(key){
        case 'v':
            verbose = true;
            break;
        case 'd':
            dport = strtoul(arg,&end,10);
            break;
        case 's':
            sport = strtoul(arg,&end,10);
            break;
		case 'c':
			count = strtoul(arg,&end,10);
			break;
		case 'l':
			local = strtoul(arg,&end,10);
			break;
        default:
		    return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static void sig_handler(int sig)
{
	exiting = true;
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct cwnd_data *d = data;
	char d_str[INET_ADDRSTRLEN];
	char s_str[INET_ADDRSTRLEN];
    int pid=d->pid;
	int send=d->send;
	int recv=d->recv;
    unsigned int saddr=d->saddr;
    unsigned int daddr=d->daddr;
    unsigned int sport=d->sport;
	unsigned int dport=d->dport;
	unsigned int total=d->total;
	if("")
    printf("%-10d %-15s %-10d %-10d %-22s %-22s %-10d %-10d %-22d\n",pid,d->comm,send,recv,inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str)),inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str)),sport,dport,total);
    return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct udp_tracing_bpf *skel;
	int err = 0;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = udp_tracing_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	if(sport){
		printf("filter open,sport:%d \n",sport);
		skel->rodata->filter_sport = sport;
	}
	
	
    /* Load & verify BPF programs */
	err = udp_tracing_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
    /* Attach tracepoints */
	err =udp_tracing_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-10s %-15s %-10s %-10s %-22s %-22s %-10s  %-10s %-22s\n" ,
		"pid","comm","send","recv","saddr","daddr" ,"sport","sport","total");
		//printf("%-22s %-22s\n","pid" ,"sum" );
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		if(count != 0 && count_i>=count)
			break;
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	udp_tracing_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}