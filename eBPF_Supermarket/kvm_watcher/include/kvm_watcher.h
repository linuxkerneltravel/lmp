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
// BPF program used for monitoring KVM event.

#ifndef __KVM_WATCHER_H
#define __KVM_WATCHER_H

#define TASK_COMM_LEN 16
#define KVM_MEM_LOG_DIRTY_PAGES (1UL << 0)

#define NS_TO_US_FACTOR 1000.0
#define NS_TO_MS_FACTOR 1000000.0

#define NS_TO_US_WITH_DECIMAL(ns) ((double)(ns) / NS_TO_US_FACTOR)
#define NS_TO_MS_WITH_DECIMAL(ns) ((double)(ns) / NS_TO_MS_FACTOR)

#define MICROSECONDS_IN_SECOND 1000000
#define OUTPUT_INTERVAL_SECONDS 0.5

#define OUTPUT_INTERVAL(us) usleep((unsigned int)(us * MICROSECONDS_IN_SECOND))

#define OPTIONS_LIST "-w, -p, -d, -f, -c, or -e"

#define PFERR_PRESENT_BIT 0
#define PFERR_WRITE_BIT 1
#define PFERR_USER_BIT 2
#define PFERR_RSVD_BIT 3
#define PFERR_FETCH_BIT 4
#define PFERR_PK_BIT 5
#define PFERR_SGX_BIT 15

#define KVM_IRQCHIP_PIC 0
#define KVM_IRQCHIP_IOAPIC 1
#define KVM_MSI 2

#define PIC_NUM_PINS 16
#define IOAPIC_NUM_PINS 24

#define PFERR_RSVD_MASK (1UL << 3)  // mmio

#define PRINT_USAGE_ERR()                                               \
    do {                                                                \
        fprintf(stderr, "Please specify exactly one option from %s.\n", \
                OPTIONS_LIST);                                          \
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);             \
    } while (0)

#define SET_OPTION_AND_CHECK_USAGE(option, value) \
    do {                                          \
        if (option == 0) {                        \
            value = true;                         \
            option = 1;                           \
        } else {                                  \
            PRINT_USAGE_ERR();                    \
        }                                         \
    } while (0)

// 定义清屏宏
#define CLEAR_SCREEN() printf("\033[2J\033[H")

#define RING_BUFFER_TIMEOUT_MS 100

#define RESERVE_RINGBUF_ENTRY(rb, e)                             \
    do {                                                         \
        typeof(e) _tmp = bpf_ringbuf_reserve(rb, sizeof(*e), 0); \
        if (!_tmp)                                               \
            return 0;                                            \
        e = _tmp;                                                \
    } while (0)

#define CHECK_PID(vm_pid)                            \
    unsigned pid = bpf_get_current_pid_tgid() >> 32; \
    if ((vm_pid) > 0 && pid != (vm_pid)) {           \
        return 0;                                    \
    }

struct ExitReason {
    int number;
    const char *name;
};

struct reason_info {
    unsigned long long time;
    unsigned long reason;
    int count;
};

struct process {
    unsigned pid;
    unsigned tid;
    char comm[TASK_COMM_LEN];
};

enum EventType {
    NONE_TYPE,
    VCPU_WAKEUP,
    EXIT,
    HALT_POLL,
    MARK_PAGE_DIRTY,
    PAGE_FAULT,
    IRQCHIP,
} event_type;

struct common_event {
    struct process process;
    unsigned long long time;

    // 成员特定于每个事件类型的数据
    union {
        struct {
            unsigned long long dur_hlt_ns;
            bool waited;
            unsigned vcpu_id;
            bool valid;
            // VCPU_WAKEUP 特有成员
        } vcpu_wakeup_data;

        struct {
            unsigned reason_number;
            unsigned long long duration_ns;
            int count;
            int total;
            // EXIT 特有成员
        } exit_data;

        struct {
            bool grow;
            unsigned int new;
            unsigned int old;
            unsigned vcpu_id;
            // HALT_POLL 特有成员
        } halt_poll_data;

        struct {
            unsigned long npages;
            unsigned long userspace_addr;
            unsigned long long rel_gfn;
            unsigned long long gfn;
            short slot_id;
            // MARK_PAGE_DIRTY 特有成员
        } mark_page_dirty_data;

        struct {
            unsigned long long delay;
            unsigned long long error_code;
            unsigned long long addr;
            unsigned long long pfn;
            unsigned long long hva;
            unsigned count;
            short memslot_id;
            // PAGE_FAULT 特有成员
        } page_fault_data;

        struct {
            unsigned long long delay;
            int ret;
            int irqchip_type;
            /*pic*/
            unsigned char chip;
            unsigned pin;
            unsigned char elcr;
            unsigned char imr;
            /*ioapic*/
            unsigned long long ioapic_bits;
            unsigned int irq_nr;
            /*msi*/
            unsigned long long address;
            unsigned long long data;
            // IRQCHIP 特有成员
        } irqchip_data;
    };
};

#endif /* __KVM_WATCHER_H */