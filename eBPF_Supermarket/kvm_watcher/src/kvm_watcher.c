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
// User space BPF program used for monitoring KVM event.

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "../include/kvm_watcher.h"
#include "kvm_watcher.skel.h"

struct ExitReason exitReasons[] = {{0, "EXCEPTION_NMI"},
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
                                   {75, "NOTIFY"}};

const char *getExitReasonName(int number) {
    for (int i = 0; i < sizeof(exitReasons) / sizeof(exitReasons[0]); i++) {
        if (exitReasons[i].number == number) {
            return exitReasons[i].name;
        }
    }
    return "Unknown";  // 如果找不到对应的退出原因，返回一个默认值
}

typedef struct {
    int exit_reason;
    char info[256];
    unsigned long long total_dur;
    unsigned long long avg_dur;
} ExitInfo;

// 链表节点
typedef struct Node {
    ExitInfo data;
    struct Node *next;
} Node;

Node *exitInfoBuffer = NULL;

void addExitInfo(Node **head, int exit_reason, const char *info,
                 unsigned long long dur, int count) {
    Node *newNode = (Node *)malloc(sizeof(Node));
    newNode->data.exit_reason = exit_reason;
    strncpy(newNode->data.info, info, sizeof(newNode->data.info));
    newNode->next = NULL;
    newNode->data.total_dur = dur;
    newNode->data.avg_dur = dur / count;

    // 检查是否已经存在相同 exit reason 的信息
    Node *current = *head;
    Node *previous = NULL;
    while (current != NULL) {
        if (current->data.exit_reason == exit_reason) {
            // 更新已存在的信息
            strncpy(current->data.info, info, sizeof(current->data.info));
            current->data.total_dur = dur + current->data.total_dur;
            current->data.avg_dur = current->data.total_dur / count;
            free(newNode);  // 释放新节点，因为信息已经更新
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
const char *findExitInfo(Node *head, int exit_reason) {
    Node *current = head;
    while (current != NULL) {
        if (current->data.exit_reason == exit_reason) {
            return current->data.info;
        }
        current = current->next;
    }
    return NULL;
}

// 释放链表
void freeExitInfoList(Node *head) {
    while (head != NULL) {
        Node *temp = head;
        head = head->next;
        free(temp);
    }
}

void printExitInfo(Node *head) {
    Node *current = head;
    printf(
        "\n-----------------------------------------------------------------"
        "----------\n");
    printf("%-23s %-10s %-15s %-8s %-13s \n", "EXIT_REASON", "COMM", "PID/TID",
           "COUNT", "AVG_DURATION(ns)");
    while (current != NULL) {
        printf("%-2d/%-20s %-33s %-13llu \n", current->data.exit_reason,
               getExitReasonName(current->data.exit_reason), current->data.info,
               current->data.avg_dur);
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
                fprintf(stderr, "Process exist!but is not vmprocess: %d\n",
                        pid);
                return 0;  // VmProcess name does not contain the target string
            }
        }
        fclose(file);
    }
    fprintf(stderr, "Process name does not find: %d\n", pid);
    return 0;  // VmProcess with the given PID not found
}

// 结构用于保存键值对
struct KeyValPair {
    unsigned long long key;
    unsigned int value;
};

// 比较函数，用于 qsort
int compare(const void *a, const void *b) {
    return ((struct KeyValPair *)b)->value - ((struct KeyValPair *)a)->value;
}

int save_count_dirtypagemap_to_file(struct bpf_map *map) {
    const char *directory = "./temp";
    const char *filename = "./temp/dirty_temp";

    // 创建目录，如果不存在
    if (mkdir(directory, 0777) == -1) {
        // 如果目录已经存在，这里的错误是预期的，可以忽略
        // 否则，打印错误信息并返回
        if (errno != EEXIST) {
            perror("Failed to create directory");
            return -1;
        }
    }

    FILE *output = fopen(filename, "w");
    if (!output) {
        perror("Failed to open output file");
        return -1;
    }

    int count_dirty_fd = bpf_map__fd(map);
    unsigned long long lookup_key = -1, next_key;
    unsigned int dirty_counts;

    // 保存键值对到数组
    struct KeyValPair *pairs = NULL;
    size_t size = 0;

    while (!bpf_map_get_next_key(count_dirty_fd, &lookup_key, &next_key)) {
        int err = bpf_map_lookup_elem(count_dirty_fd, &next_key, &dirty_counts);
        if (err < 0) {
            fprintf(stderr, "failed to lookup dirty page: %d\n", err);
            fclose(output);
            free(pairs);
            return -1;
        }

        // 保存到数组
        pairs = realloc(pairs, (size + 1) * sizeof(struct KeyValPair));
        pairs[size].key = next_key;
        pairs[size].value = dirty_counts;
        size++;

        // 删除元素
        err = bpf_map_delete_elem(count_dirty_fd, &next_key);
        if (err < 0) {
            fprintf(stderr, "failed to cleanup dirty page: %d\n", err);
            fclose(output);
            free(pairs);
            return -1;
        }
    }

    // 对数组进行排序
    qsort(pairs, size, sizeof(struct KeyValPair), compare);

    // 输出到文件
    for (size_t i = 0; i < size; i++) {
        fprintf(output, "%llx             %d\n", pairs[i].key, pairs[i].value);
    }

    fclose(output);
    free(pairs);
    return 0;
}

static struct env {
    bool execute_vcpu_wakeup;
    bool execute_exit;
    bool ShowStats;
    bool execute_halt_poll_ns;
    bool execute_mark_page_dirty;
    bool execute_page_fault;
    int monitoring_time;
    pid_t vm_pid;
} env = {
    .execute_vcpu_wakeup = false,
    .execute_exit = false,
    .ShowStats = false,
    .execute_halt_poll_ns = false,
    .execute_mark_page_dirty = false,
    .execute_page_fault = false,
    .monitoring_time = 0,
    .vm_pid = -1,
};

const char *argp_program_version = "kvm_watcher 1.0";
const char *argp_program_bug_address = "<nanshuaibo811@163.com>";
const char argp_program_doc[] = "BPF program used for monitoring KVM event\n";
int option_selected = 0;  // 功能标志变量,确保激活子功能

static const struct argp_option opts[] = {
    {"vcpu_wakeup", 'w', NULL, 0, "Monitoring the wakeup of vcpu."},
    {"vm_exit", 'e', NULL, 0, "Monitoring the event of vm exit."},
    {"vcpu_halt_poll_ns", 'n', NULL, 0,
     "Monitoring the variation in vCPU polling time."},
    {"mark_page_dirty", 'd', NULL, 0,
     "Monitor virtual machine dirty page information."},
    {"kvmmmu_page_fault", 'f', NULL, 0,
     "Monitoring the date of kvmmmu page fault."},
    {"stat", 's', NULL, 0,
     "Display statistical data.(The -e option must be specified.)"},
    {"vm_pid", 'p', "PID", 0, "Specify the virtual machine pid to monitor."},
    {"monitoring_time", 't', "SEC", 0, "Time for monitoring event."},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 'w':
            SET_OPTION_AND_CHECK_USAGE(option_selected,
                                       env.execute_vcpu_wakeup);
            break;
        case 'e':
            SET_OPTION_AND_CHECK_USAGE(option_selected, env.execute_exit);
            break;
        case 'n':
            SET_OPTION_AND_CHECK_USAGE(option_selected,
                                       env.execute_halt_poll_ns);
            break;
        case 'd':
            SET_OPTION_AND_CHECK_USAGE(option_selected,
                                       env.execute_mark_page_dirty);
            break;
        case 'f':
            SET_OPTION_AND_CHECK_USAGE(option_selected, env.execute_page_fault);
            break;
        case 's':
            if (env.execute_exit) {
                env.ShowStats = true;
            } else {
                fprintf(stderr, "The -e option must be specified.\n");
                argp_usage(state);
            }
            break;
        case 't':
            env.monitoring_time = strtol(arg, NULL, 10);
            if (env.monitoring_time <= 0) {
                fprintf(stderr, "Invalid duration: %s\n", arg);
                argp_usage(state);
            } else if (!option_selected) {
                fprintf(stderr, "No monitoring options activated!\n");
                argp_usage(state);
            } else {
                alarm(env.monitoring_time);
            }
            break;
        case 'p':
            env.vm_pid = strtol(arg, NULL, 10);
            if (env.vm_pid <= 0 || doesVmProcessExist(env.vm_pid) == 0) {
                fprintf(stderr, "Invalid vm_pid: %s\n", arg);
                argp_usage(state);
            }
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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    if (env.execute_vcpu_wakeup) {
        const struct vcpu_wakeup_event *e = data;
        printf("%-18llu %-20llu %-15s %-6d/%-8d %-10s\n", e->hlt_time,
               e->dur_hlt_ns, e->process.comm, e->process.pid, e->process.tid,
               e->waited ? "wait" : "poll");
    } else if (env.execute_exit) {
        char info_buffer[256];
        const struct exit_event *e = data;
        printf("%-18llu %-2d/%-20s %-10s %-6u/%-8u %-8d %-13llu \n", e->time,
               e->reason_number, getExitReasonName(e->reason_number),
               e->process.comm, e->process.pid, e->process.tid, e->count,
               e->duration_ns);
        if (env.ShowStats) {
            snprintf(info_buffer, sizeof(info_buffer), "%-10s %-6u/%-8u %-8d",
                     e->process.comm, e->process.pid, e->process.tid, e->count);
            addExitInfo(&exitInfoBuffer, e->reason_number, info_buffer,
                        e->duration_ns, e->count);
        }
    } else if (env.execute_halt_poll_ns) {
        const struct halt_poll_ns_event *e = data;
        printf("%-18llu %-15s %-6d/%-8d %-10s %-7d --> %d \n", e->time,
               e->process.comm, e->process.pid, e->process.tid,
               e->grow ? "grow" : "shrink", e->old, e->new);
    } else if (env.execute_mark_page_dirty) {
        const struct mark_page_dirty_in_slot_event *e = data;
        printf("%-18llu %-15s %-6d/%-8d %-10llx %-10llx %-10lu %-15lx %d \n",
               e->time, e->process.comm, e->process.pid, e->process.tid, e->gfn,
               e->rel_gfn, e->npages, e->userspace_addr, e->slot_id);
    } else if (env.execute_page_fault) {
        const struct page_fault_event *e = data;
        printf(
            "%-18llu %-10s %-10u %-12llx %-6u %-10llu %-20llx %-17llx %-10d ",
            e->time, e->process.comm, e->process.pid, e->addr, e->count,
            e->delay, e->hva, e->pfn, e->memslot_id);
        if (e->error_code & (1ULL << PFERR_PRESENT_BIT)) {
            printf("Present ");
        }
        if (e->error_code & (1ULL << PFERR_WRITE_BIT)) {
            printf("Write ");
        }
        if (e->error_code & (1ULL << PFERR_USER_BIT)) {
            printf("User ");
        }
        if (e->error_code & (1ULL << PFERR_RSVD_BIT)) {
            printf("Reserved ");
        }
        if (e->error_code & (1ULL << PFERR_FETCH_BIT)) {
            printf("Exec ");
        }
        if (e->error_code & (1ULL << PFERR_PK_BIT)) {
            printf("Protection-Key ");
        }
        if (e->error_code & (1ULL << PFERR_SGX_BIT)) {
            printf("SGX ");
        }
        printf("\n");
    }
    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct kvm_watcher_bpf *skel;
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
    skel = kvm_watcher_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Parameterize BPF code with parameter */
    skel->rodata->vm_pid = env.vm_pid;

    /* Disable or load kernel hook functions */
    bpf_program__set_autoload(skel->progs.tp_vcpu_wakeup,
                              env.execute_vcpu_wakeup ? true : false);
    bpf_program__set_autoload(skel->progs.tp_exit,
                              env.execute_exit ? true : false);
    bpf_program__set_autoload(skel->progs.tp_entry,
                              env.execute_exit ? true : false);
    bpf_program__set_autoload(skel->progs.tp_kvm_halt_poll_ns,
                              env.execute_halt_poll_ns ? true : false);
    bpf_program__set_autoload(skel->progs.kp_mark_page_dirty_in_slot,
                              env.execute_mark_page_dirty ? true : false);
    bpf_program__set_autoload(skel->progs.tp_page_fault,
                              env.execute_page_fault ? true : false);
    bpf_program__set_autoload(skel->progs.fexit_direct_page_fault,
                              env.execute_page_fault ? true : false);
    /* Load & verify BPF programs */
    err = kvm_watcher_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = kvm_watcher_bpf__attach(skel);
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
    if (env.execute_vcpu_wakeup) {
        printf("%-18s %-20s %-15s %-15s %-10s\n", "HLT_TIME(ns)",
               "DURATIONS_TIME(ns)", "VCPUID/COMM", "PID/TID", "WAIT/POLL");
    } else if (env.execute_exit) {
        printf("%-18s %-23s %-10s %-15s %-8s %-13s \n", "TIME", "EXIT_REASON",
               "COMM", "PID/TID", "COUNT", "DURATION(ns)");
    } else if (env.execute_halt_poll_ns) {
        printf("%-18s %-15s %-15s %-10s %-11s %-10s\n", "TIME(ns)",
               "VCPUID/COMM", "PID/TID", "TYPE", "OLD(ns)", "NEW(ns)");
    } else if (env.execute_mark_page_dirty) {
        printf("%-18s %-15s %-15s %-10s %-11s %-10s %-10s %-10s\n", "TIME(ns)",
               "VCPUID/COMM", "PID/TID", "GFN", "REL_GFN", "NPAGES",
               "USERSPACE_ADDR", "SLOT_ID");
    } else if (env.execute_page_fault) {
        printf("%-18s %-10s %-10s %-12s %-6s %-10s %-20s %-17s %-10s %-10s\n",
               "TIMESTAMP", "COMM", "PID", "ADDRESS", "COUNT", "DELAY", "HVA",
               "PFN", "MEM_SLOTID", "ERROR_TYPE");
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
    if (env.ShowStats) {
        printExitInfo(exitInfoBuffer);
        freeExitInfoList(exitInfoBuffer);
    } else if (env.execute_mark_page_dirty) {
        err = save_count_dirtypagemap_to_file(skel->maps.count_dirty_map);
        if (err < 0) {
            printf("Save count dirty page map to file fail: %d\n", err);
            goto cleanup;
        }
    }
cleanup:
    ring_buffer__free(rb);
    kvm_watcher_bpf__destroy(skel);
    return -err;
}
