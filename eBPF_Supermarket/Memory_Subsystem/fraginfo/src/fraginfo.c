#include "fraginfo.skel.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "fraginfo.h"

static struct env {
    int interval;
    int duration;
} env = {
    .interval = 1,
    .duration = 10,
};

const char *argp_program_version = "fraginfo 0.1";
const char *argp_program_bug_address = "<your_email@example.com>";
const char argp_program_doc[] = 
"Fraginfo BPF program.\n"
"\n"
"USAGE: ./fraginfo [--interval INTERVAL] [--duration DURATION]\n";

static const struct argp_option opts[] = {
    { "interval", 'i', "INTERVAL", 0, "Print interval in seconds (default 1)"},
    { "duration", 'd', "DURATION", 0, "Total duration in seconds to run (default 10)"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
    case 'i':
        env.interval = atoi(arg);
        break;
    case 'd':
        env.duration = atoi(arg);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

void print_nodes(int fd) {
    struct pgdat_info pinfo;
    __u64 key = 0, next_key;
    printf(" Node ID          PGDAT_PTR       NR_ZONES \n");
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(fd, &next_key, &pinfo);
        printf(" %5d       0x%llx  %5d\n",
               pinfo.node_id, pinfo.pgdat_ptr, pinfo.nr_zones);
        key = next_key;
    }
}

void print_zones(int fd) {
    struct zone_info zinfo;
    __u64 key = 0, next_key;
    printf(" COMM          ZONE_PTR       ZONE_PFN  SUM_PAGES FACT_PAGES \n");
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        bpf_map_lookup_elem(fd, &next_key, &zinfo);
        printf(" %s       0x%llx   %llu       %5llu   %llu  \n", zinfo.comm, zinfo.zone_ptr, zinfo.zone_start_pfn,zinfo.spanned_pages,zinfo.present_pages);
        key = next_key;
    }
}

int main(int argc, char **argv) {
    struct fraginfo_bpf *skel;
    int err;

    struct argp argp = { opts, parse_arg, NULL, argp_program_doc };
    err = argp_parse(&argp, argc, argv, 0, 0, NULL);
    if (err)
        return err;

    // libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = fraginfo_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = fraginfo_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    err = fraginfo_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Tracing... Press Ctrl-C to end.\n");

    while (!exiting) {
        sleep(env.interval);
        print_nodes(bpf_map__fd(skel->maps.nodes));
        print_zones(bpf_map__fd(skel->maps.zones));
    }

cleanup:
    fraginfo_bpf__destroy(skel);
    return -err;
}