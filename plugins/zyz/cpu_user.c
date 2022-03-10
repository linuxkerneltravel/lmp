#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "perf-sys.h"

#define SAMPLE_PERIOD 0x7fffffffffffffffULL

static int map_fd[1];

static int pmufd_cyl[32];


static void register_perf(int cpu, struct perf_event_attr *attr) {

    pmufd_cyl[cpu] = sys_perf_event_open(attr, -1, cpu, -1, 0);

    ioctl(pmufd_cyl[cpu], PERF_EVENT_IOC_RESET, 0);
    ioctl(pmufd_cyl[cpu], PERF_EVENT_IOC_ENABLE, 0);

    bpf_map_update_elem(map_fd[0], &cpu, &(pmufd_cyl[cpu]), BPF_ANY);
}

int main(int argc, char **argv) {
    struct bpf_link *links[1];
    struct bpf_program *prog;
    struct bpf_object *obj;
    char filename[256];
    int i, nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);

    struct perf_event_attr attr_cycles = {
        .freq = 0,
        .sample_period = SAMPLE_PERIOD,
        .inherit = 0,
        .type = PERF_TYPE_HARDWARE,
        .read_format = 0,
        .sample_type = 0,
        .config = PERF_COUNT_HW_CPU_CYCLES,
    };

    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opending BPF object file failed\n");
        return 0;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object failed\n");
        return -1;
    }

    map_fd[0] = bpf_object__find_map_fd_by_name(obj, "pmu_cyl");

    if (map_fd[0] < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        return -1;
    }

    bpf_object__for_each_program(prog, obj) {
        links[i] = bpf_program__attach(prog);
        if (libbpf_get_error(links[i])) {
            fprintf(stderr, "ERROR: bpf_program__attach failed\n");
            links[i] = NULL;
            return 0;
        }
        i++;
    }

    for (i = 0; i < nr_cpus; i++) {
        register_perf(i, &attr_cycles);
    }

    while(1) {
        read_trace_pipe();
	//sleep(1);
	//printf("===\n");
    }


    return 0;
}

