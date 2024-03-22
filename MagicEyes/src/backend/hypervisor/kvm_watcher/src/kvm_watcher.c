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

#include "kvm_watcher/include/kvm_watcher.h"

#include "hypervisor/kvm_watcher/kvm_watcher.skel.h"

// 创建并打开临时文件
FILE *create_temp_file(const char *filename) {
    const char *directory = "./temp";
    char filepath[256];

    // 构建文件的完整路径
    snprintf(filepath, sizeof(filepath), "%s/%s", directory, filename);

    // 创建目录，如果不存在
    if (mkdir(directory, 0777) == -1 && errno != EEXIST) {
        perror("Failed to create directory");
        return NULL;
    }

    // 尝试打开文件
    FILE *output = fopen(filepath, "w");
    if (!output) {
        perror("Failed to open output file");
        return NULL;
    }

    return output;
}

const char *getName(int number, enum EventType type) {
    struct NameMapping {
        int number;
        const char *name;
    };
    // 定义具体的退出原因 arch/x86/include/uapi/asm/vmx.h
    struct NameMapping exitReasons[] = {{0, "EXCEPTION_NMI"},
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
    // 定义超级调用 include\uapi\linux\kvm_para.h
    struct NameMapping hypercalls[] = {
        {1, "VAPIC_POLL_IRQ"}, {5, "KICK_CPU"},     {9, "CLOCK_PAIRING"},
        {10, "SEND_IPI"},      {11, "SCHED_YIELD"}, {12, "MAP_GPA_RANGE"}};
    // 根据枚举类型选择使用哪个结构体数组进行转换
    struct NameMapping *mappings;
    int count;
    switch (type) {
        case EXIT:
            mappings = exitReasons;
            count = sizeof(exitReasons) / sizeof(exitReasons[0]);
            break;
        case HYPERCALL:
            mappings = hypercalls;
            count = sizeof(hypercalls) / sizeof(hypercalls[0]);
            break;
        default:
            return "Unknown";
    }

    // 根据给定的编号在选择的结构体数组中搜索对应的名称
    for (int i = 0; i < count; i++) {
        if (mappings[i].number == number) {
            return mappings[i].name;
        }
    }

    return "Unknown";  // 如果找不到对应的条目，返回一个默认值
}

// 检查具有给定 PID 的进程是否存在
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
            // 查看是否进程文件中是否出现"qemu-system"字符串
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

// 定义键值对结构体
struct KeyValPair {
    struct dirty_page_info key;
    unsigned int value;
};

// 比较函数，用于排序
int compare(const void *a, const void *b) {
    return (((struct KeyValPair *)b)->value - ((struct KeyValPair *)a)->value);
}

// 保存脏页信息到文件
int save_count_dirtypagemap_to_file(struct bpf_map *map) {
    const char *filename = "dirty_temp";
    FILE *output = create_temp_file(filename);
    if (!output) {
        fprintf(stderr, "Failed to create file in directory\n");
        return 1;
    }
    int count_dirty_fd = bpf_map__fd(map);
    struct dirty_page_info lookup_key = {};
    struct dirty_page_info next_key = {};
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

        // 更新 lookup_key
        lookup_key = next_key;
    }

    // 对数组进行排序
    qsort(pairs, size, sizeof(struct KeyValPair), compare);

    // 输出到文件
    fprintf(output, "%-10s %-10s %-10s %-10s %s\n", "PID", "GFN", "REL_GFN",
            "SLOT_ID", "COUNTS");
    for (size_t i = 0; i < size; i++) {
        fprintf(output, "%-10d %-10llx %-10llx %-10d %u\n", pairs[i].key.pid,
                pairs[i].key.gfn, pairs[i].key.rel_gfn, pairs[i].key.slot_id,
                pairs[i].value);
    }

    fclose(output);
    free(pairs);
    return 0;
}
// 定义env结构体，用来存储程序中的事件信息
static struct env {
    bool execute_vcpu_wakeup;
    bool execute_exit;
    bool execute_halt_poll_ns;
    bool execute_mark_page_dirty;
    bool execute_page_fault;
    bool mmio_page_fault;
    bool execute_irqchip;
    bool execute_irq_inject;
    bool execute_hypercall;
    bool execute_ioctl;
    int monitoring_time;
    pid_t vm_pid;
    enum EventType event_type;
} env = {
    .execute_vcpu_wakeup = false,
    .execute_exit = false,
    .execute_halt_poll_ns = false,
    .execute_mark_page_dirty = false,
    .execute_page_fault = false,
    .execute_irqchip = false,
    .execute_irq_inject = false,
    .mmio_page_fault = false,
    .execute_hypercall = false,
    .execute_ioctl = false,
    .monitoring_time = 0,
    .vm_pid = -1,
    .event_type = NONE_TYPE,
};

const char *argp_program_version = "kvm_watcher 1.0";
const char *argp_program_bug_address = "<nanshuaibo811@163.com>";
const char argp_program_doc[] = "BPF program used for monitoring KVM event\n";
int option_selected = 0;  // 功能标志变量,确保激活子功能
// 具体解释命令行参数
static const struct argp_option opts[] = {
    {"vcpu_wakeup", 'w', NULL, 0, "Monitoring the wakeup of vcpu."},
    {"vm_exit", 'e', NULL, 0, "Monitoring the event of vm exit."},
    {"halt_poll_ns", 'n', NULL, 0,
     "Monitoring the variation in vCPU halt-polling time."},
    {"mark_page_dirty", 'd', NULL, 0,
     "Monitor virtual machine dirty page information."},
    {"kvmmmu_page_fault", 'f', NULL, 0,
     "Monitoring the data of kvmmmu page fault."},
    {"kvm_irqchip", 'c', NULL, 0,
     "Monitor the irqchip setting information in KVM VM."},
    {"irq_inject", 'i', NULL, 0,
     "Monitor the virq injection information in KVM VM "},
    {"hypercall", 'h', NULL, 0, "Monitor the hypercall information in KVM VM "},
    {"mmio", 'm', NULL, 0,
     "Monitoring the data of mmio page fault.(The -f option must be "
     "specified.)"},
    {"vm_pid", 'p', "PID", 0, "Specify the virtual machine pid to monitor."},
    {"monitoring_time", 't', "SEC", 0, "Time for monitoring."},
    {"kvm_ioctl", 'l', NULL, 0, "Monitoring the KVM IOCTL."},
    {NULL, 'H', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};
// 解析命令行参数
static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 'H':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
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
        case 'c':
            SET_OPTION_AND_CHECK_USAGE(option_selected, env.execute_irqchip);
            break;
        case 'i':
            SET_OPTION_AND_CHECK_USAGE(option_selected, env.execute_irq_inject);
            break;
        case 'h':
            SET_OPTION_AND_CHECK_USAGE(option_selected, env.execute_hypercall);
            break;
        case 'l':
            SET_OPTION_AND_CHECK_USAGE(option_selected, env.execute_ioctl);
            break;
        case 'm':
            if (env.execute_page_fault) {
                env.mmio_page_fault = true;
            } else {
                fprintf(stderr, "The -f option must be specified.\n");
                argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
            }
            break;
        case 't':
            env.monitoring_time = strtol(arg, NULL, 10);
            if (env.monitoring_time <= 0) {
                fprintf(stderr, "Invalid duration: %s\n", arg);
                argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
            } else if (!option_selected) {
                fprintf(stderr, "No monitoring options activated!\n");
                argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
            } else {
                alarm(env.monitoring_time);
            }
            break;
        case 'p':
            env.vm_pid = strtol(arg, NULL, 10);
            if (env.vm_pid <= 0 || doesVmProcessExist(env.vm_pid) == 0) {
                fprintf(stderr, "Invalid vm_pid: %s\n", arg);
                argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
            }
            break;
        case ARGP_KEY_ARG:
            argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
// 定义解析参数的处理函数
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
// 设置信号来控制是否打印信息
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
    } else if (env->execute_irqchip) {
        env->event_type = IRQCHIP;
    } else if (env->execute_irq_inject) {
        env->event_type = IRQ_INJECT;
    } else if (env->execute_hypercall) {
        env->event_type = HYPERCALL;
    } else if (env->execute_ioctl) {
        env->event_type = IOCTL;
    } else {
        env->event_type = NONE_TYPE;  // 或者根据需要设置一个默认的事件类型
    }
    return 0;
}

/*环形缓冲区的处理函数，用来打印ringbuff中的数据（最后展示的数据行）*/
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct common_event *e = data;
    double timestamp_ms = NS_TO_MS_WITH_DECIMAL(e->time);
    switch (env.event_type) {
        case VCPU_WAKEUP: {
            // 使用 e->vcpu_wakeup_data 访问 VCPU_WAKEUP 特有成员
            printf("%-18.6f %-20.6f %-15s %-6d/%-8d %-10d %-10s %-10s\n",
                   timestamp_ms,
                   NS_TO_MS_WITH_DECIMAL(e->vcpu_wakeup_data.dur_hlt_ns),
                   e->process.comm, e->process.pid, e->process.tid,
                   e->vcpu_wakeup_data.vcpu_id,
                   e->vcpu_wakeup_data.waited ? "wait" : "poll",
                   e->vcpu_wakeup_data.valid ? "valid" : "invalid");
            break;
        }
        case EXIT: {
            break;
        }
        case HALT_POLL: {
            // 使用 e->halt_poll_data 访问 HALT_POLL 特有成员
            printf("%-18.6f %-15s %-6d/%-8d %-10s %-7d %-7d --> %d \n",
                   timestamp_ms, e->process.comm, e->process.pid,
                   e->process.tid, e->halt_poll_data.grow ? "grow" : "shrink",
                   e->halt_poll_data.vcpu_id, e->halt_poll_data.old,
                   e->halt_poll_data.new);
            break;
        }
        case MARK_PAGE_DIRTY: {
            // 使用 e->mark_page_dirty_data 访问 MARK_PAGE_DIRTY 特有成员
            printf(
                "%-18.6f %-15s %-6d/%-8d %-10llx %-10llx %-10llu %-15llx %d \n",
                timestamp_ms, e->process.comm, e->process.pid, e->process.tid,
                e->mark_page_dirty_data.gfn, e->mark_page_dirty_data.rel_gfn,
                e->mark_page_dirty_data.npages,
                e->mark_page_dirty_data.userspace_addr,
                e->mark_page_dirty_data.slot_id);
            break;
        }
        case PAGE_FAULT: {
            // 使用 e->page_fault_data 访问 PAGE_FAULT 特有成员
            printf("%-18.6f %-15s %-10u %-14llx %-6u %-10.4f ", timestamp_ms,
                   e->process.comm, e->process.pid, e->page_fault_data.addr,
                   e->page_fault_data.count,
                   NS_TO_US_WITH_DECIMAL(e->page_fault_data.delay));
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
        case IRQCHIP: {
            const char *delivery_modes[] = {"Fixed", "LowPrio", "SMI",
                                            "Res3",  "NMI",     "INIT",
                                            "SIPI",  "ExtINT"};
            // 使用 e->irqchip_data 访问 IRQCHIP 特有成员
            switch (e->irqchip_data.irqchip_type) {
                case KVM_IRQCHIP_PIC:
                    printf(
                        "%-18.6f %-15s %-10d %-10llu %-10s/%-3u "
                        "%-3s/%-6s "
                        "%-7s|%-8s|%-5s|%-6s|"
                        "%s\n",
                        timestamp_ms, e->process.comm, e->process.pid,
                        e->irqchip_data.delay,
                        e->irqchip_data.chip ? "PIC slave" : "PIC master",
                        e->irqchip_data.pin, "-", "-", "-", "-",
                        (e->irqchip_data.elcr & (1 << e->irqchip_data.pin))
                            ? "level"
                            : "edge",
                        (e->irqchip_data.imr & (1 << e->irqchip_data.pin))
                            ? "masked"
                            : "-",
                        e->irqchip_data.ret == 0 ? "coalesced" : "-");
                    break;
                case KVM_IRQCHIP_IOAPIC:
                    printf(
                        "%-18.6f %-15s %-10d %-10llu %-10s/%-3u "
                        "%#-3x/%-6u "
                        "%-7s|%-8s|%-5s|%-6s|"
                        "%s\n",
                        timestamp_ms, e->process.comm, e->process.pid,
                        e->irqchip_data.delay, "IOAPIC", e->irqchip_data.pin,
                        (unsigned char)(e->irqchip_data.ioapic_bits >> 56),
                        (unsigned char)e->irqchip_data.ioapic_bits,
                        delivery_modes[e->irqchip_data.ioapic_bits >> 8 & 0x7],
                        (e->irqchip_data.ioapic_bits & (1 << 11)) ? "logical"
                                                                  : "physical",
                        (e->irqchip_data.ioapic_bits & (1 << 15)) ? "level"
                                                                  : "edge",
                        (e->irqchip_data.ioapic_bits & (1 << 16)) ? "masked"
                                                                  : "-",
                        e->irqchip_data.ret == 0 ? "coalesced" : "-");
                    break;

                case KVM_MSI:
                    printf(
                        "%-18.6f %-15s %-10d %-10llu %-10s/%-3s "
                        "%#-3llx/%-6u "
                        "%-7s|%-8s|%-5s|%-6s|"
                        "%s\n",
                        timestamp_ms, e->process.comm, e->process.pid,
                        e->irqchip_data.delay, "MSI", "-",
                        (unsigned char)(e->irqchip_data.address >> 12) |
                            ((e->irqchip_data.address >> 32) & 0xffffff00),
                        (unsigned char)e->irqchip_data.data,
                        delivery_modes[e->irqchip_data.data >> 8 & 0x7],
                        (e->irqchip_data.address & (1 << 2)) ? "logical"
                                                             : "physical",
                        (e->irqchip_data.data & (1 << 15)) ? "level" : "edge",
                        (e->irqchip_data.address & (1 << 3)) ? "rh" : "-", "-");
                    break;

                default:
                    break;
            }
            break;
        }
        case IRQ_INJECT: {
            printf("%-18.6f %-15s %-10d %-10lld %#-10x %-10d %-10lld %-10s\n",
                   timestamp_ms, e->process.comm, e->process.pid,
                   e->irq_inject_data.delay, e->irq_inject_data.irq_nr,
                   e->irq_inject_data.vcpu_id, e->irq_inject_data.injections,
                   e->irq_inject_data.soft ? "Soft/INTn" : "IRQ");
            break;
        }
        case HYPERCALL: {
            const char *filename = "./temp/hc_temp";
            FILE *output = fopen(filename, "a");
            if (!output) {
                perror("Failed to open output file");
                return -1;
            }
            fprintf(output, "%-18.6f %-15s %-10d %-10d %-10s %-11llu",
                    timestamp_ms, e->process.comm, e->process.pid,
                    e->hypercall_data.vcpu_id,
                    getName(e->hypercall_data.hc_nr, HYPERCALL),
                    e->hypercall_data.hypercalls);
            if (e->hypercall_data.hc_nr == 5) {
                fprintf(output, "apic_id:%llu\n", e->hypercall_data.a1);
            } else if (e->hypercall_data.hc_nr == 9) {
                fprintf(
                    output, "GPA:%#llx CLOCK_TYPE:%s\n", e->hypercall_data.a0,
                    e->hypercall_data.a1 == 0 ? "KVM_CLOCK_PAIRING_WALLCLOCK"
                                              : "");
            } else if (e->hypercall_data.hc_nr == 10) {
                fprintf(output,
                        "ipi_bitmap_low:%#llx,ipi_bitmap_high:%#llx,min(apic_"
                        "id):%llu,icr:%#llx\n",
                        e->hypercall_data.a0, e->hypercall_data.a1,
                        e->hypercall_data.a2, e->hypercall_data.a3);
            } else if (e->hypercall_data.hc_nr == 11) {
                fprintf(output, "dest apic_id:%llu\n", e->hypercall_data.a0);
            } else if (e->hypercall_data.hc_nr == 12) {
                fprintf(output,
                        "GPA start:%#llx,PAGE_NR(4KB):%llu,Attributes:%#llx\n",
                        e->hypercall_data.a0, e->hypercall_data.a1,
                        e->hypercall_data.a2);
            } else {
                fprintf(output, "\n");
            }
            fclose(output);
            break;
        }
        case IOCTL: {
            break;
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
            printf("%-18s %-20s %-15s %-15s %-10s %-10s %-10s\n", "TIME(ms)",
                   "DUR_HALT(ms)", "COMM", "PID/TID", "VCPU_ID", "WAIT/POLL",
                   "VAILD?");
            break;
        case EXIT:
            break;
        case HALT_POLL:
            printf("%-18s %-15s %-15s %-10s %-7s %-11s %-10s\n", "TIME(ms)",
                   "COMM", "PID/TID", "TYPE", "VCPU_ID", "OLD(ns)", "NEW(ns)");
            break;
        case MARK_PAGE_DIRTY:
            printf("%-18s %-15s %-15s %-10s %-10s %-10s %-10s %-10s\n",
                   "TIME(ms)", "COMM", "PID/TID", "GFN", "REL_GFN", "NPAGES",
                   "USERSPACE_ADDR", "SLOT_ID");
            break;
        case PAGE_FAULT:
            printf("%-18s %-15s %-10s %-12s %-6s %-10s %-20s %-17s %-10s %s\n",
                   "TIME(ms)", "COMM", "PID", "(f(GPA)m(GFN))", "COUNT",
                   "DELAY(us)", "HVA", "PFN", "MEM_SLOTID", "ERROR_TYPE");
            break;
        case IRQCHIP:
            printf("%-18s %-15s %-10s %-10s %-14s %-10s %-10s\n", "TIME(ms)",
                   "COMM", "PID", "DELAY", "CHIP/PIN", "DST/VEC", "OTHERS");
            break;
        case IRQ_INJECT:
            printf("%-18s %-15s %-10s %-10s %-10s %-10s %-10s %-10s\n",
                   "TIME(ms)", "COMM", "PID", "DELAY", "IRQ_NR", "VCPU_ID",
                   "INJECTIONS", "TYPE");
            break;
        case HYPERCALL: {
            const char *filename = "hc_temp";
            FILE *output = create_temp_file(filename);
            if (!output) {
                fprintf(stderr, "Failed to create file in directory\n");
                return 1;
            }
            fprintf(output, "%-18s %-15s %-10s %-10s %-10s %-10s %-10s\n",
                    "TIME(ms)", "COMM", "PID", "VCPU_ID", "NAME", "HYPERCALLS",
                    "ARGS");
            fclose(output);
            break;
        }
        case IOCTL: {
            printf("wait....\n");
            break;
        }
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
    bpf_program__set_autoload(skel->progs.fexit_tdp_page_fault,
                              env.execute_page_fault ? true : false);
    bpf_program__set_autoload(skel->progs.fentry_kvm_mmu_page_fault,
                              env.mmio_page_fault ? true : false);
    bpf_program__set_autoload(skel->progs.tp_handle_mmio_page_fault,
                              env.mmio_page_fault ? true : false);
    bpf_program__set_autoload(skel->progs.fentry_kvm_pic_set_irq,
                              env.execute_irqchip ? true : false);
    bpf_program__set_autoload(skel->progs.fexit_kvm_pic_set_irq,
                              env.execute_irqchip ? true : false);
    bpf_program__set_autoload(skel->progs.fentry_kvm_ioapic_set_irq,
                              env.execute_irqchip ? true : false);
    bpf_program__set_autoload(skel->progs.fexit_kvm_ioapic_set_irq,
                              env.execute_irqchip ? true : false);
    bpf_program__set_autoload(skel->progs.fentry_kvm_set_msi_irq,
                              env.execute_irqchip ? true : false);
    bpf_program__set_autoload(skel->progs.fexit_kvm_set_msi_irq,
                              env.execute_irqchip ? true : false);
    bpf_program__set_autoload(skel->progs.fentry_vmx_inject_irq,
                              env.execute_irq_inject ? true : false);
    bpf_program__set_autoload(skel->progs.fexit_vmx_inject_irq,
                              env.execute_irq_inject ? true : false);
    bpf_program__set_autoload(skel->progs.fentry_emulate_hypercall,
                              env.execute_hypercall ? true : false);
    bpf_program__set_autoload(skel->progs.tp_ioctl,
                              env.execute_ioctl ? true : false);
}

// 函数不接受参数，返回一个静态分配的字符串
const char *getCurrentTimeFormatted() {
    static char ts[32];  // 静态分配，每次调用都会覆盖
    time_t t;
    struct tm *tm;

    time(&t);
    tm = localtime(&t);

    // 格式化时间到静态分配的字符串中
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    return ts;  // 返回指向静态字符串的指针
}

int print_hc_map(struct kvm_watcher_bpf *skel) {
    int fd = bpf_map__fd(skel->maps.hc_map);
    int count_fd = bpf_map__fd(skel->maps.hc_count);
    int err;
    struct hc_key lookup_key = {};
    struct hc_key next_key = {};
    struct hc_value hc_value = {};
    int first_run = 1;
    // Iterate over the map
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        if (first_run) {
            first_run = 0;
            printf(
                "--------------------------------------------------------------"
                "----------"
                "\n");
            printf("TIME:%s\n", getCurrentTimeFormatted());
            printf("%-12s %-12s %-12s %-12s %-12s\n", "PID", "VCPU_ID", "NAME",
                   "COUNTS", "HYPERCALLS");
        }
        // Print the current entry
        err = bpf_map_lookup_elem(fd, &next_key, &hc_value);
        if (err < 0) {
            fprintf(stderr, "failed to lookup hc_value: %d\n", err);
            return -1;
        }
        printf("%-12d %-12d %-12s %-12d %-12lld\n", next_key.pid,
               next_key.vcpu_id, getName(next_key.nr, HYPERCALL),
               hc_value.counts, hc_value.hypercalls);
        // // Move to the next key
        lookup_key = next_key;
    }
    memset(&lookup_key, 0, sizeof(struct hc_key));
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_delete_elem(fd, &next_key);
        if (err < 0) {
            fprintf(stderr, "failed to cleanup hc_map: %d\n", err);
            return -1;
        }
        lookup_key = next_key;
    }
    memset(&lookup_key, 0, sizeof(struct hc_key));
    while (!bpf_map_get_next_key(count_fd, &lookup_key, &next_key)) {
        err = bpf_map_delete_elem(count_fd, &next_key);
        if (err < 0) {
            fprintf(stderr, "failed to cleanup hc_count: %d\n", err);
            return -1;
        }
        lookup_key = next_key;
    }
    return 0;
}
// In order to sort vm_exit maps
int sort_by_key(struct kvm_watcher_bpf *skel, struct exit_key *keys,
                struct exit_value *values) {
    int fd = bpf_map__fd(skel->maps.exit_map);
    int err = 0;
    struct exit_key lookup_key = {};
    struct exit_key next_key = {};
    struct exit_value exit_value;
    int first = 1;
    int i = 0, j;
    int count = 0;
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        count++;
        if (first) {
            first = 0;
            bpf_map_lookup_elem(fd, &next_key, &exit_value);
            keys[0] = next_key;
            values[0] = exit_value;
            i++;
            continue;
        }
        err = bpf_map_lookup_elem(fd, &next_key, &exit_value);

        if (err < 0) {
            fprintf(stderr, "failed to lookup exit_value: %d\n", err);
            return -1;
        }
        // insert sort
        j = i - 1;
        struct exit_key temp_key = next_key;
        struct exit_value temp_value = exit_value;
        while (j >= 0 &&
               (keys[j].pid > temp_key.pid || (keys[j].tid > temp_key.tid))) {
            keys[j + 1] = keys[j];
            values[j + 1] = values[j];
            j--;
        }
        i++;
        keys[j + 1] = next_key;
        values[j + 1] = temp_value;
        // Move to the next key
        lookup_key = next_key;
    }
    return count;
}
int print_exit_map(struct kvm_watcher_bpf *skel) {
    int fd = bpf_map__fd(skel->maps.exit_map);
    int err;
    struct exit_key lookup_key = {};
    struct exit_key next_key = {};
    int first_run = 1;
    struct exit_key keys[8192];
    struct exit_value values[8192];
    int count = sort_by_key(skel, keys, values);
    // Iterate over the array
    __u32 pid = 0;
    __u32 tid = 0;
    for (int i = 0; i < count; i++) {
        if (first_run) {
            first_run = 0;
            printf("\nTIME:%s\n", getCurrentTimeFormatted());
            printf("%-12s %-12s %-12s %-12s %-12s %-12s %-12s\n", "pid", "tid",
                   "total_time", "max_time", "min_time", "counts", "reason");
            printf(
                "------------ ------------ ------------ ------------ "
                "------------ "
                "------------ "
                "------------\n");
        }
        // Print the current entry
        if (tid == 0 || tid != keys[i].tid) {
            tid = keys[i].tid;
            if (pid == 0 || pid != keys[i].pid) {
                pid = keys[i].pid;
                printf("%-13d", pid);
            } else {
                printf("%-13s", "");
            }
            printf("%-12d %-12.4f %-12.4f %-12.4f %-12u %-12s\n", keys[i].tid,
                   NS_TO_MS_WITH_DECIMAL(values[i].total_time),
                   NS_TO_MS_WITH_DECIMAL(values[i].max_time),
                   NS_TO_MS_WITH_DECIMAL(values[i].min_time), values[i].count,
                   getName(keys[i].reason, EXIT));
        } else if (tid == keys[i].tid) {
            printf("%25s %-12.4f %-12.4f %-12.4f %-12u %-12s\n", "",
                   NS_TO_MS_WITH_DECIMAL(values[i].total_time),
                   NS_TO_MS_WITH_DECIMAL(values[i].max_time),
                   NS_TO_MS_WITH_DECIMAL(values[i].min_time), values[i].count,
                  getName(keys[i].reason, EXIT));
        }
    }
    // clear the maps
    memset(&lookup_key, 0, sizeof(struct exit_key));
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        err = bpf_map_delete_elem(fd, &next_key);
        if (err < 0) {
            fprintf(stderr, "failed to cleanup counters: %d\n", err);
            return -1;
        }
        lookup_key = next_key;
    }
    return 0;
}

void print_map_and_check_error(int (*print_func)(struct kvm_watcher_bpf *),
                               struct kvm_watcher_bpf *skel,
                               const char *map_name, int err) {
    OUTPUT_INTERVAL(2);
    print_func(skel);
    if (err < 0) {
        printf("Error printing %s map: %d\n", map_name, err);
    }
}

int main(int argc, char **argv) {
    // 定义一个环形缓冲区
    struct ring_buffer *rb = NULL;
    struct kvm_watcher_bpf *skel;
    int err;

    /*解析命令行参数*/
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

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

    /* 禁用或加载内核挂钩函数 */
    set_disable_load(skel);

    /* 加载并验证BPF程序 */
    err = kvm_watcher_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* 附加跟踪点处理程序 */
    err = kvm_watcher_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

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

        if (env.execute_hypercall) {
            print_map_and_check_error(print_hc_map, skel, "hypercall", err);
        }
        if (env.execute_exit) {
            print_map_and_check_error(print_exit_map, skel, "exit", err);
        }
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
    if (env.execute_mark_page_dirty) {
        err = save_count_dirtypagemap_to_file(skel->maps.count_dirty_map);
        if (err < 0) {
            printf("Save count dirty page map to file fail: %d\n", err);
            goto cleanup;
        } else {
            printf("\nSave count dirty page map to file success!\n");
            goto cleanup;
        }
    }
cleanup:
    ring_buffer__free(rb);
    kvm_watcher_bpf__destroy(skel);
    return -err;
}