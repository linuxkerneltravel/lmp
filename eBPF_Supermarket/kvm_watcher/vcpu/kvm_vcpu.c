// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: nanshuaibo811@163.com
//
// User space BPF program used for monitoring data for vCPU.


#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include <argp.h>
#include <bpf/libbpf.h>
#include "kvm_vcpu.skel.h"
#include "kvm_vcpu.h"

static struct env {
	bool vcpu_wakeup;
} env={
	.vcpu_wakeup=false,
};

const char *argp_program_version = "kvm_vcpu 1.0";
const char *argp_program_bug_address = "<nanshuaibo811@163.com>";
const char argp_program_doc[] = "BPF program used for monitoring data for vCPU\n";

static const struct argp_option opts[] = {
	{ "vcpu_wakeup", 'w', NULL, 0, "Set the time for profiling VM exit event reasons" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
    case 'w':
        env.vcpu_wakeup=true;
        break;
	case ARGP_KEY_ARG:
		argp_usage(state);
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


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	printf("%-18llu %-20llu %-15s %-6d/%-8d %-10s\n", e->hlt_time,e->block_ns, e->comm, e->pid,e->tid,e->waited ? "wait" : "poll");

	return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
	struct kvm_vcpu_bpf *skel;
	int err;

    /* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Open BPF application */
	skel = kvm_vcpu_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	/* Parameterize BPF code with parameter */
	skel->rodata->execute_vcpu_wake = env.vcpu_wakeup;

	/* Load & verify BPF programs */
	err = kvm_vcpu_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = kvm_vcpu_bpf__attach(skel);
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
	if(env.vcpu_wakeup){
		printf("%-18s %-20s %-15s %-15s %-10s\n", "HLT_TIME(us)", "DURATIONS_TIME(ns)","VCPUID/COMM","PID/TID","WAIT/POLL");
	}
	while (!exiting) {
		err = ring_buffer__poll(rb, 10 /* timeout, ms */);
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
	ring_buffer__free(rb);
	kvm_vcpu_bpf__destroy(skel);
	return -err;
}
