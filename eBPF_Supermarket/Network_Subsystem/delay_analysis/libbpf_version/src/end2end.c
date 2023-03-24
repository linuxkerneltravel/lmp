#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <malloc.h>

#include "end2end.h"
#include "end2end.skel.h"

int count,count_i;
int sport,dport;
int __pkt_time_info_map_fd;

static volatile bool exiting = false;
bool verbose = false;

#define get_time(n) ((time_info.time[n]-time_info.time[0])*1e-6)

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


static int handle_event(void *ctx,void *data, size_t data_sz)
{
    struct pkt_time_info time_info;
    int err = bpf_map_lookup_and_delete_elem(__pkt_time_info_map_fd, data , &time_info);
	if (err < 0) {
		fprintf(stderr, "failed to lookup map: %d\n", err);
		return -1;
	}
    
    const struct packet_tuple *d = data;
    char saddr[INET_ADDRSTRLEN],daddr[INET_ADDRSTRLEN];
    struct sockaddr_in sockaddr;
    sockaddr.sin_addr.s_addr = d->saddr;
    inet_ntop(AF_INET, &sockaddr.sin_addr, saddr, sizeof(saddr));
    sockaddr.sin_addr.s_addr = d->daddr;
    inet_ntop(AF_INET, &sockaddr.sin_addr, daddr, sizeof(daddr));


    printf("%s:%d->%s:%d,seq:%u,ack:%u\n",saddr,d->sport,daddr,d->dport,d->seq,d->ack);
    printf("[rcv]dev:%f,ip:%f,tcp:%f,socket:%f\n\n",get_time(2),get_time(3),get_time(4),get_time(1));
    
    return 0;
}

void test_data(){
    ;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
    struct end2end_bpf *skel;
	int err = 0;
    test_data();
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = end2end_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

    /* Parameterize BPF code */
    skel->rodata->filter_dport = dport;
    skel->rodata->filter_sport = sport;

    /* Load & verify BPF programs */
	err = end2end_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    /* Attach tracepoints */
	err = end2end_bpf__attach(skel);
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

    __pkt_time_info_map_fd = bpf_map__fd(skel->maps.pkt_time_info_map);

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
	}

cleanup:
	/* Clean up */
	end2end_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}