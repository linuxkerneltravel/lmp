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
//定义具体的退出原因
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
//打印退出的信息
void printExitInfo(Node *head) {
    Node *current = head;
    CLEAR_SCREEN();
    printf(
        "-----------------------------------------------------------------"
        "----------\n");
    printf("%-21s %-18s %-8s %-8s %-13s \n", "EXIT_REASON", "COMM", "PID",
           "COUNT", "AVG_DURATION(ns)");
    while (current != NULL) {
        printf("%-2d/%-18s %-33s %-13llu \n", current->data.exit_reason,
               getExitReasonName(current->data.exit_reason), current->data.info,
               current->data.avg_dur);
        current = current->next;
    }
}
//检查具有给定 PID 的进程是否存在
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
            //查看是否进程文件中是否出现"qemu-system"字符串
            if (strstr(proc_name, "qemu-system") != NULL) {
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
//保存脏页信息到./temp/dirty_temp文件中
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
//定义env结构体，用来存储程序中的事件信息
static struct env {
    bool execute_vcpu_wakeup;
    bool execute_exit;
    bool ShowStats;
    bool execute_halt_poll_ns;
    bool execute_mark_page_dirty;
    bool execute_page_fault;
    bool mmio_page_fault;
    bool execute_pic;
    int monitoring_time;
    pid_t vm_pid;
    enum EventType event_type;
} env = {
    .execute_vcpu_wakeup = false,
    .execute_exit = false,
    .ShowStats = false,
    .execute_halt_poll_ns = false,
    .execute_mark_page_dirty = false,
    .execute_page_fault = false,
    .execute_pic = false,
    .mmio_page_fault = false,
    .monitoring_time = 0,
    .vm_pid = -1,
    .event_type = NONE_TYPE,
};

const char *argp_program_version = "kvm_watcher 1.0";
const char *argp_program_bug_address = "<nanshuaibo811@163.com>";
const char argp_program_doc[] = "BPF program used for monitoring KVM event\n";
int option_selected = 0;  // 功能标志变量,确保激活子功能
//具体解释命令行参数
static const struct argp_option opts[] = {
    {"vcpu_wakeup", 'w', NULL, 0, "Monitoring the wakeup of vcpu."},
    {"vm_exit", 'e', NULL, 0, "Monitoring the event of vm exit."},
    {"halt_poll_ns", 'n', NULL, 0,
     "Monitoring the variation in vCPU halt-polling time."},
    {"mark_page_dirty", 'd', NULL, 0,
     "Monitor virtual machine dirty page information."},
    {"kvmmmu_page_fault", 'f', NULL, 0,
     "Monitoring the data of kvmmmu page fault."},
    {"kvm_irq", 'i', NULL, 0, "Monitor the interrupt information in KVM VM."},
    {"stat", 's', NULL, 0,
     "Display statistical data.(The -e option must be specified.)"},
    {"mmio", 'm', NULL, 0,
     "Monitoring the data of mmio page fault..(The -f option must be "
     "specified.)"},
    {"vm_pid", 'p', "PID", 0, "Specify the virtual machine pid to monitor."},
    {"monitoring_time", 't', "SEC", 0, "Time for monitoring."},
    {},
};
//解析命令行参数
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
        case 'i':
            SET_OPTION_AND_CHECK_USAGE(option_selected, env.execute_pic);
            break;
        case 's':
            if (env.execute_exit) {
                env.ShowStats = true;
            } else {
                fprintf(stderr, "The -e option must be specified.\n");
                argp_usage(state);
            }
            break;
        case 'm':
            if (env.execute_page_fault) {
                env.mmio_page_fault = true;
            } else {
                fprintf(stderr, "The -f option must be specified.\n");
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
//定义解析参数的处理函数
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
//设置信号来控制是否打印信息
static void sig_handler(int sig) {
    exiting = true;
}

// 根据 env 设置 EventType
static int determineEventType(struct env *env) {
    if (!env) {
        return 1;
    }
    if (env->execute_vcpu_wakeup) {
        env->event_type = VCPU_WAKEUP;
    } else if (env->execute_exit) {
        env->event_type = EXIT;
    } else if (env->execute_halt_poll_ns) {
        env->event_type = HALT_POLL;
    } else if (env->execute_mark_page_dirty) {
        env->event_type = MARK_PAGE_DIRTY;
    } else if (env->execute_page_fault) {
        env->event_type = PAGE_FAULT;
    } else if (env->execute_pic) {
        env->event_type = PIC;
    } else {
        env->event_type = NONE_TYPE;  // 或者根据需要设置一个默认的事件类型
    }
    return 0;
}

//获取中断控制器的类型
const char *get_irqchip(unsigned char chip) {
    if (chip >= KVM_NR_IRQCHIPS) {
        return "Invalid";
    } else if (chip == KVM_IRQCHIP_PIC_MASTER) {
        return "master";
    } else if (chip == KVM_IRQCHIP_PIC_SLAVE) {
        return "slave";
    } else if (chip == KVM_IRQCHIP_IOAPIC) {
        return "ioapic";
    } else {
        return "Unknown";
    }
}
/*环形缓冲区的处理函数，用来打印ringbuff中的数据（最后展示的数据行）*/
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct common_event *e = data;
    switch (env.event_type) {
        case VCPU_WAKEUP: {
            // 使用 e->vcpu_wakeup_data 访问 VCPU_WAKEUP 特有成员
            printf("%-18llu %-20llu %-15s %-6d/%-8d %-10d %-10s %-10s\n",
                   e->time, NS_TO_US(e->vcpu_wakeup_data.dur_hlt_ns),
                   e->process.comm, e->process.pid, e->process.tid,
                   e->vcpu_wakeup_data.vcpu_id,
                   e->vcpu_wakeup_data.waited ? "wait" : "poll",
                   e->vcpu_wakeup_data.valid ? "valid" : "invalid");
            break;
        }
        case EXIT: {
            char info_buffer[256];
            // 使用 e->exit_data 访问 EXIT 特有成员
            printf("%-18llu %-2d/%-18s %-18s %-6u/%-8u %-8d %-13llu \n",
                   e->time, e->exit_data.reason_number,
                   getExitReasonName(e->exit_data.reason_number),
                   e->process.comm, e->process.pid, e->process.tid,
                   e->exit_data.count, e->exit_data.duration_ns);

            if (env.ShowStats) {
                snprintf(info_buffer, sizeof(info_buffer), "%-18s %-8u %-8d",
                         e->process.comm, e->process.pid, e->exit_data.count);
                addExitInfo(&exitInfoBuffer, e->exit_data.reason_number,
                            info_buffer, e->exit_data.duration_ns,
                            e->exit_data.count);
            }
            break;
        }
        case HALT_POLL: {
            // 使用 e->halt_poll_data 访问 HALT_POLL 特有成员
            printf("%-18llu %-15s %-6d/%-8d %-10s %-7d %-7d --> %d \n", e->time,
                   e->process.comm, e->process.pid, e->process.tid,
                   e->halt_poll_data.grow ? "grow" : "shrink",
                   e->halt_poll_data.vcpu_id, e->halt_poll_data.old,
                   e->halt_poll_data.new);
            break;
        }
        case MARK_PAGE_DIRTY: {
            // 使用 e->mark_page_dirty_data 访问 MARK_PAGE_DIRTY 特有成员
            printf(
                "%-18llu %-15s %-6d/%-8d %-10llx %-10llx %-10lu %-15lx %d \n",
                e->time, e->process.comm, e->process.pid, e->process.tid,
                e->mark_page_dirty_data.gfn, e->mark_page_dirty_data.rel_gfn,
                e->mark_page_dirty_data.npages,
                e->mark_page_dirty_data.userspace_addr,
                e->mark_page_dirty_data.slot_id);
            break;
        }
        case PAGE_FAULT: {
            // 使用 e->page_fault_data 访问 PAGE_FAULT 特有成员
            printf("%-18llu %-15s %-10u %-12llx %-6u %-10llu ", e->time,
                   e->process.comm, e->process.pid, e->page_fault_data.addr,
                   e->page_fault_data.count, e->page_fault_data.delay);
            if (e->page_fault_data.error_code & (1ULL << PFERR_RSVD_BIT)) {
                printf("%-20s %-17s %-10s", "-", "-", "-");
            } else {
                printf("%-20llx %-17llx %-10d", e->page_fault_data.hva,
                       e->page_fault_data.pfn, e->page_fault_data.memslot_id);
            }
            if (e->page_fault_data.error_code & (1ULL << PFERR_PRESENT_BIT)) {
                printf(" Present");
            }
            if (e->page_fault_data.error_code & (1ULL << PFERR_WRITE_BIT)) {
                printf(" Write");
            }
            if (e->page_fault_data.error_code & (1ULL << PFERR_USER_BIT)) {
                printf(" User");
            }
            if (e->page_fault_data.error_code & (1ULL << PFERR_RSVD_BIT)) {
                printf(" Reserved(MMIO)");
                /*IOAPIC 的mmio基址 #define IOAPIC_DEFAULT_BASE_ADDRESS
                 * 0xfec00000*/
            }
            if (e->page_fault_data.error_code & (1ULL << PFERR_FETCH_BIT)) {
                printf(" Exec");
            }
            if (e->page_fault_data.error_code & (1ULL << PFERR_PK_BIT)) {
                printf(" Protection-Key");
            }
            if (e->page_fault_data.error_code & (1ULL << PFERR_SGX_BIT)) {
                printf(" SGX");
            }
            printf("\n");
            break;
        }
        case PIC: {
            // 使用 e->pic_data 访问 PAGE_FAULT 特有成员
            if (e->pic_data.ioapic) {
                const char *ioapic_delivery_modes[] = {
                    "Fixed", "LowPrio", "SMI",  "Res3",
                    "NMI",   "INIT",    "SIPI", "ExtINT"};
                printf(
                    "%-18llu %-15s %-10d %-10llu %-6s/%-3u %-10d %-3x/%-6u "
                    "%-5s | %-8s | %-5s | %-6s | "
                    "%s\n",
                    e->time, e->process.comm, e->process.pid, e->pic_data.delay,
                    "ioapic", e->pic_data.pin, e->pic_data.irq_source_id,
                    (unsigned char)(e->pic_data.ioapic_bits >> 56),
                    (unsigned char)e->pic_data.ioapic_bits,
                    ioapic_delivery_modes[e->pic_data.ioapic_bits >> 8 & 0x7],
                    (e->pic_data.ioapic_bits & (1 << 11)) ? "logical"
                                                          : "physical",
                    (e->pic_data.ioapic_bits & (1 << 15)) ? "level" : "edge",
                    (e->pic_data.ioapic_bits & (1 << 16)) ? "masked" : "-",
                    e->pic_data.ret == 0 ? "coalesced" : "-");
            } else {
                printf(
                    "%-18llu %-15s %-10d %-10llu %-10s/%-3u %-10d %-3s/%-6s "
                    "%-5s | %-8s | %-5s | %-6s | "
                    "%s\n",
                    e->time, e->process.comm, e->process.pid, e->pic_data.delay,
                    e->pic_data.chip ? "PIC slave" : "PIC master",
                    e->pic_data.pin, e->pic_data.irq_source_id, "-", "-", "-",
                    "-",
                    (e->pic_data.elcr & (1 << e->pic_data.pin)) ? "level"
                                                                : "edge",
                    (e->pic_data.imr & (1 << e->pic_data.pin)) ? "masked" : "-",
                    e->pic_data.ret == 0 ? "coalesced" : "-");
            }
        }
        default:
            // 处理未知事件类型
            break;
    }

    return 0;
}
/*通过env->event_type属性来选择需要打印的信息表头*/
static int print_event_head(struct env *env) {
    if (!env->event_type) {
        // 处理无效参数，可以选择抛出错误或返回
        return 1;
    }
    switch (env->event_type) {
        case VCPU_WAKEUP:
            printf("%-18s %-20s %-15s %-15s %-10s %-10s %-10s\n", "TIME(ns)",
                   "DUR_HALT(us)", "COMM", "PID/TID", "VCPU_ID", "WAIT/POLL",
                   "VAILD?");
            break;
        case EXIT:
            printf("%-18s %-21s %-18s %-15s %-8s %-13s \n", "TIME(ns)",
                   "EXIT_REASON", "COMM", "PID/TID", "COUNT", "DURATION(ns)");
            break;
        case HALT_POLL:
            printf("%-18s %-15s %-15s %-10s %-7s %-11s %-10s\n", "TIME(ns)",
                   "COMM", "PID/TID", "TYPE", "VCPU_ID", "OLD(ns)", "NEW(ns)");
            break;
        case MARK_PAGE_DIRTY:
            printf("%-18s %-15s %-15s %-10s %-10s %-10s %-10s %-10s\n",
                   "TIME(ns)", "COMM", "PID/TID", "GFN", "REL_GFN", "NPAGES",
                   "USERSPACE_ADDR", "SLOT_ID");
            break;
        case PAGE_FAULT:
            printf("%-18s %-15s %-10s %-12s %-6s %-10s %-20s %-17s %-10s %s\n",
                   "TIMESTAMP", "COMM", "PID", "ADDRESS", "COUNT", "DELAY",
                   "HVA", "PFN", "MEM_SLOTID", "ERROR_TYPE");
            break;
        case PIC:
            printf("%-18s %-15s %-10s %-10s %-14s %-10s %-10s %-10s\n",
                   "TIMESTAMP", "COMM", "PID", "DELAY", "CHIP/PIN", "SOURCE_ID",
                   "DST/VEC", "OTHERS");
        default:
            // Handle default case or display an error message
            break;
    }
    return 0;
}
/*通过env结构体的属性真值来判断是否加载某个挂载函数*/
static void set_disable_load(struct kvm_watcher_bpf *skel) {
    bpf_program__set_autoload(skel->progs.tp_vcpu_wakeup,
                              env.execute_vcpu_wakeup ? true : false);
    bpf_program__set_autoload(skel->progs.fentry_kvm_vcpu_halt,
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
    bpf_program__set_autoload(skel->progs.fentry_kvm_mmu_page_fault,
                              env.mmio_page_fault ? true : false);
    bpf_program__set_autoload(skel->progs.fexit_handle_mmio_page_fault,
                              env.mmio_page_fault ? true : false);
    bpf_program__set_autoload(skel->progs.fentry_kvm_pic_set_irq,
                              env.execute_pic ? true : false);
    bpf_program__set_autoload(skel->progs.fexit_kvm_pic_set_irq,
                              env.execute_pic ? true : false);
    bpf_program__set_autoload(skel->progs.fentry_kvm_ioapic_set_irq, false);
    bpf_program__set_autoload(skel->progs.fexit_kvm_ioapic_set_irq, false);
}

int main(int argc, char **argv) {
    //定义一个环形缓冲区
    struct ring_buffer *rb = NULL;
    struct kvm_watcher_bpf *skel;
    int err;

    /* Parse command line arguments */
    /*解析命令行参数*/
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Set up libbpf errors and debug info callback */
    /*设置libbpf的错误和调试信息回调*/
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
    /* 禁用或加载内核挂钩函数 */
    set_disable_load(skel);

    /* Load & verify BPF programs */
    /* 加载并验证BPF程序 */
    err = kvm_watcher_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    /* 附加跟踪点处理程序 */
    err = kvm_watcher_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    /* 设置环形缓冲区轮询 */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // 根据 env 设置 EventType
    err = determineEventType(&env);
    if (err) {
        fprintf(stderr, "Invalid env parm\n");
        goto cleanup;
    }

    // 清屏
    if (option_selected) {
        CLEAR_SCREEN();
    }

    /*打印信息头*/
    err = print_event_head(&env);
    if (err) {
        fprintf(stderr, "Please specify an option using %s.\n", OPTIONS_LIST);
        goto cleanup;
    }
    while (!exiting) {
        err = ring_buffer__poll(rb, RING_BUFFER_TIMEOUT_MS /* timeout, ms */);
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
