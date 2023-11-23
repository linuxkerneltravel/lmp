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
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>
#include <argp.h>
#include <bpf/libbpf.h>
#include "kvm_exits.skel.h"
#include "kvm_exits.h"


// 存储所有exit reason的映射关系
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

typedef struct {
    	int exit_reason;
    	char info[256]; // 替换成适当的大小
	unsigned long long total_dur;
	unsigned long long avg_dur;
} ExitInfo;

// 链表节点
typedef struct Node {
    	ExitInfo data;
    	struct Node* next;
} Node;

Node* exitInfoBuffer = NULL;

void addExitInfo(Node** head, int exit_reason, const char* info,unsigned long long dur,int count) {
    Node* newNode = (Node*)malloc(sizeof(Node));
    newNode->data.exit_reason = exit_reason;
    strncpy(newNode->data.info, info, sizeof(newNode->data.info));
    newNode->next = NULL;
    newNode->data.total_dur = dur;
    newNode->data.avg_dur = dur / count;

    // 检查是否已经存在相同 exit reason 的信息
    Node* current = *head;
    Node* previous = NULL;
    while (current != NULL) {
        if (current->data.exit_reason == exit_reason) {
            // 更新已存在的信息
            strncpy(current->data.info, info, sizeof(current->data.info));
	    current->data.total_dur=dur+current->data.total_dur;
	    current->data.avg_dur=current->data.total_dur/count;
            free(newNode); // 释放新节点，因为信息已经更新
            return;
        }
        previous = current;
        current = current->next;
    }
    // 没有找到相同的 exit reason，将新节点添加到链表
    if (previous != NULL) {
        previous->next = newNode;
    } else {
        *head = newNode;
    }
}

// 查找指定退出原因的信息
const char* findExitInfo(Node* head, int exit_reason) {
    Node* current = head;
    while (current != NULL) {
        if (current->data.exit_reason == exit_reason) {
            return current->data.info;
        }
        current = current->next;
    }
    return NULL;
}

// 释放链表
void freeExitInfoList(Node* head) {
    while (head != NULL) {
        Node* temp = head;
        head = head->next;
        free(temp);
    }
}

void printExitInfo(Node* head) {
    Node* current = head;
    printf("%-23s %-10s %-14s %-8s %-13s \n", "EXIT_REASON", "COMM","PID/TID","COUNT","AVG_DURATION(ns)"/*,"PCT"*/);
    while (current != NULL) {
		printf("%-2d/%-20s %-32s %-13llu \n", current->data.exit_reason,getExitReasonName(current->data.exit_reason), current->data.info,current->data.avg_dur);
       	 	current = current->next;
    }
}

int doesVmProcessExist(pid_t pid) {
    char proc_name[256];
    snprintf(proc_name, sizeof(proc_name), "/proc/%d/cmdline", pid);
    FILE *file = fopen(proc_name, "r");
    if (file) {
        size_t size;
        size = fread(proc_name, 1, sizeof(proc_name), file);
        if (size > 0) {
            if (proc_name[size - 1] == '\n') {
                proc_name[size - 1] = '\0';  // Remove newline character
            }
            if (strstr(proc_name, "qemu-system-x86_64") != NULL) {
                fclose(file);
                return 1;  // VmProcess name contains the target string
            } else {
                fclose(file);
				fprintf(stderr, "Process exist!but is not vmprocess: %d\n", pid);
                return 0;  // VmProcess name does not contain the target string
            }
        }
        fclose(file);
    }
    fprintf(stderr, "Process name does not find: %d\n", pid);
    return 0;  // VmProcess with the given PID not found
}

static struct env {
	int monitoring_time;
	pid_t vm_pid;
    int stat;
} env={
	.monitoring_time=0,
	.vm_pid=0,
    .stat=0,
};

const char *argp_program_version = "kvm_exits 1.0";
const char *argp_program_bug_address = "<nanshuaibo811@163.com>";
const char argp_program_doc[] = "BPF program used for outputting VM exit reason\n";

static const struct argp_option opts[] = {
	{ "monitoring_time", 't', "TIME-SEC", 0, "Set the time for profiling VM exit event reasons" },
	{ "vm_pid", 'p', "PID", 0, "Specify the virtual machine pid to monitor." },
    { "stat",'s',"STAT",0,"After monitoring is completed, display statistical data." },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 't':
		errno = 0;
		env.monitoring_time = strtol(arg, NULL, 10);
		if (errno || env.monitoring_time <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
        else{
            alarm(env.monitoring_time);
        }
		break;
	case 'p':
		env.vm_pid=strtol(arg, NULL, 10);
		if(env.vm_pid<=0 || doesVmProcessExist(env.vm_pid)==0 ){
			fprintf(stderr, "Invalid vm_pid: %s\n", arg);
			argp_usage(state);
		}
		break;
    case 's':
        env.stat = strtol(arg, NULL, 10);
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
	char info_buffer[256];
	printf("%-2d/%-20s %-10s %-5u/%-8u %-8d %-13llu \n", e->reason_number,getExitReasonName(e->reason_number), e->comm, e->pid,e->tid,e->count,e->duration_ns/*,(double)e->count / e->total * 100.0*/);
	snprintf(info_buffer, sizeof(info_buffer), "%-10s %-5u/%-8u %-8d", e->comm, e->pid,e->tid,e->count);
	addExitInfo(&exitInfoBuffer,e->reason_number,info_buffer,e->duration_ns,e->count);
	return 0;
}

int main(int argc, char **argv)
{
    	struct ring_buffer *rb = NULL;
	struct kvm_exits_bpf *skel;
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
    	signal(SIGALRM, sig_handler);
	/* Open BPF application */
	skel = kvm_exits_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	skel->rodata->vm_pid = env.vm_pid;
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
	printf("%-23s %-10s %-14s %-8s %-13s \n", "EXIT_REASON", "COMM","PID/TID","COUNT","DURATION(ns)"/*,"PCT"*/);
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
    if(env.stat){
        printf("\n---------------------------------------------------------------------------\n");
        printExitInfo(exitInfoBuffer);
        freeExitInfoList(exitInfoBuffer);
    }
cleanup:
    /* Clean up */
	ring_buffer__free(rb);
	kvm_exits_bpf__destroy(skel);
	return -err;
}
