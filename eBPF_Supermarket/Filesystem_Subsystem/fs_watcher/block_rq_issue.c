#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "block_rq_issue.h"
#include "block_rq_issue.skel.h"
#include <inttypes.h>  // For PRIu64
#include <stdint.h>    // For uint32_t, uint64_t
#include <unistd.h>    // For getpid()

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event_block_rq_issue(void *ctx, void *data, unsigned long data_sz) {
    const struct event *e = data;

    printf("%-10llu %-9d %-7d %-4d %-16s Total I/O: %" PRIu64 "\n",
           e->timestamp, e->dev, e->sector, e->nr_sectors, e->comm, e->total_io);
    return 0;
}


int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct block_rq_issue_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open BPF application */
    skel = block_rq_issue_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = block_rq_issue_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = block_rq_issue_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_block_rq_issue, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("%-10s %-9s %-7s %-4s %-16s %-12s\n", "TIME", "DEV", "SECTOR", "RWBS", "COMM", "Total I/O");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }

        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        } 
    }

cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    block_rq_issue_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
