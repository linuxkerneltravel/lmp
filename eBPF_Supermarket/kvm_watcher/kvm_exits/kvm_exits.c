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
// User space BPF program used for outputting VM exit reason.

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "kvm_exits.skel.h"
#include "kvm_exits.h"

// 存储所有退出原因的映射关系
// from arch/x86/include/uapi/asm/vmx.h
struct ExitReason exitReasons[] = {
    {0, "EXCEPTION_NMI"},
    {1, "EXTERNAL_INTERRUPT"},
    {2, "TRIPLE_FAULT"},
    {3, "INIT_SIGNAL"},
    {4, "SIPI_SIGNAL"},
    {7, "INTERRUPT_WINDOW"},
    {8, "NMI_WINDOW"},
    {9, "TASK_SWITCH"},
    {10, "CPUID"},
    {12, "HLT"},
    {13, "INVD"},
    {14, "INVLPG"},
    {15, "RDPMC"},
    {16, "RDTSC"},
    {18, "VMCALL"},
    {19, "VMCLEAR"},
    {20, "VMLAUNCH"},
    {21, "VMPTRLD"},
    {22, "VMPTRST"},
    {23, "VMREAD"},
    {24, "VMRESUME"},
    {25, "VMWRITE"},
    {26, "VMOFF"},
    {27, "VMON"},
    {28, "CR_ACCESS"},
    {29, "DR_ACCESS"},
    {30, "IO_INSTRUCTION"},
    {31, "MSR_READ"},
    {32, "MSR_WRITE"},
    {33, "INVALID_STATE"},
    {34, "MSR_LOAD_FAIL"},
    {36, "MWAIT_INSTRUCTION"},
    {37, "MONITOR_TRAP_FLAG"},
    {39, "MONITOR_INSTRUCTION"},
    {40, "PAUSE_INSTRUCTION"},
    {41, "MCE_DURING_VMENTRY"},
    {43, "TPR_BELOW_THRESHOLD"},
    {44, "APIC_ACCESS"},
    {45, "EOI_INDUCED"},
    {46, "GDTR_IDTR"},
    {47, "LDTR_TR"},
    {48, "EPT_VIOLATION"},
    {49, "EPT_MISCONFIG"},
    {50, "INVEPT"},
    {51, "RDTSCP"},
    {52, "PREEMPTION_TIMER"},
    {53, "INVVPID"},
    {54, "WBINVD"},
    {55, "XSETBV"},
    {56, "APIC_WRITE"},
    {57, "RDRAND"},
    {58, "INVPCID"},
    {59, "VMFUNC"},
    {60, "ENCLS"},
    {61, "RDSEED"},
    {62, "PML_FULL"},
    {63, "XSAVES"},
    {64, "XRSTORS"},
    {67, "UMWAIT"},
    {68, "TPAUSE"},
    {74, "BUS_LOCK"},
    {75, "NOTIFY"}
};


const char* getExitReasonName(int number) {
    for (int i = 0; i < sizeof(exitReasons) / sizeof(exitReasons[0]); i++) {
        if (exitReasons[i].number == number) {
            return exitReasons[i].name;
        }
    }
    return "Unknown"; // 如果找不到对应的退出原因，返回一个默认值
}

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
	printf("%-2d/%-20s %-10s %-5u/%-8u %-10d %-12llu %.2f%%\n", e->reason_number,getExitReasonName(e->reason_number), e->comm, e->pid,e->tid,e->count,e->duration_ns,(double)e->count / e->total * 100.0);

	return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
	struct kvm_exits_bpf *skel;
	int err;

    alarm(3);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
    signal(SIGALRM, sig_handler);
	/* Open BPF application */
	skel = kvm_exits_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = kvm_exits_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = kvm_exits_bpf__attach(skel);
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
	printf("%-23s %-10s %-14s %-10s %-11s  %-10s \n", "EXIT_REASON", "COMM","PID/TID","COUNT","DURATION(ns)","PCT");
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
	kvm_exits_bpf__destroy(skel);
	return -err;
}
