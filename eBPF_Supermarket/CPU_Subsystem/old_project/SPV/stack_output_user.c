#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "trace_helpers.h"

static int map_fd[2];

static void print_ksym(__u64 addr)
{
    struct ksym *sym;

    if (!addr)
        return;
    
    sym = ksym_search(addr);
    if (!sym) {
        printf("ERROR: ksym not found!\n");
        return;
    }

    printf("%s : %llx\n", sym->name, addr);
}

#define TASK_COMM_LEN 16

struct key_t {
    __u32 pid;
    __u32 cpu;
};

struct val_t {
    char comm[TASK_COMM_LEN];
    __u32 stack_id;
};

static void print_stack_info(struct key_t *key, struct val_t *val) {
    __u64 ip[PERF_MAX_STACK_DEPTH] = {};
    int i;

    printf("CPU: %d    PID: %d    COMM: %s\n", key->cpu, key->pid, val->comm);
    printf("function call:\n");

    if (bpf_map_lookup_elem(map_fd[1], &(val->stack_id), ip) != 0) {
        printf("---NONE---\n");
    } else {
        for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--)
            print_ksym(ip[i]);
	printf("=========\n");
    }
}

static void print_function_call() {
    struct key_t key = {}, next_key;
    struct val_t val;

    while (bpf_map_get_next_key(map_fd[0], &key, &next_key) == 0) {
        bpf_map_lookup_elem(map_fd[0], &next_key, &val);
        print_stack_info(&next_key, &val);
        key = next_key;
    }

}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_link *links[2];
    struct bpf_program *prog;
    int i = 0;
    char filename[256];

    if (load_kallsyms()) {
        printf("failed to process /proc/kallsyms\n");
        return 1;
    }

    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opending BPF object file failed\n");
        obj = NULL;
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object failed\n");
        return 1;
    }

    map_fd[0] = bpf_object__find_map_fd_by_name(obj, "task_info");
    map_fd[1] = bpf_object__find_map_fd_by_name(obj, "stackmap");
    if (map_fd[0] < 0 || map_fd[1] < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        return 1;
    }

    bpf_object__for_each_program(prog, obj) {
        links[i] = bpf_program__attach(prog);
        if (libbpf_get_error(links[i])) {
            fprintf(stderr, "ERROR: bpf_program__attch failed\n");
            links[i] = NULL;
            return 1;
        }
        i++;
    }

    while (1) {
        sleep(1);
        print_function_call();
        printf("||||||||||||||||||||||||||\n");
    }

    return 0;

}
