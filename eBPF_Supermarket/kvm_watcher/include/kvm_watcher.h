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

#define OUTPUT_INTERVAL(SECONDS) sleep(SECONDS)

#define OPTIONS_LIST "-w, -p, -d, -f, -c, -i, ,-h or -e"

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
#define CLEAR_SCREEN() printf("\033[2J\033[H\n")

#define RING_BUFFER_TIMEOUT_MS 100

#define RESERVE_RINGBUF_ENTRY(rb, e)                             \
    do {                                                         \
        typeof(e) _tmp = bpf_ringbuf_reserve(rb, sizeof(*e), 0); \
        if (!_tmp)                                               \
            return 0;                                            \
        e = _tmp;                                                \
    } while (0)

#define CHECK_PID(vm_pid)                         \
    __u32 pid = bpf_get_current_pid_tgid() >> 32; \
    if ((vm_pid) > 0 && pid != (vm_pid)) {        \
        return 0;                                 \
    }

struct reason_info {
    __u64 time;
    __u64 reason;
};

struct exit_key {
    __u64 reason;
    __u32 pid;
    __u32 tid;
};

struct exit_value {
    __u64 max_time;
    __u64 total_time;
    __u64 min_time;
    __u32 count;
    __u32 pad;
};

struct dirty_page_info {
    __u64 gfn;
    __u64 rel_gfn;
    __u16 slot_id;
    __u16 pad;
    __u32 pid;
};

struct hc_value {
    __u64 a0;
    __u64 a1;
    __u64 a2;
    __u64 a3;
    __u64 hypercalls;  // vcpu上hypercall发生的次数
    __u32 counts;      // 特定hypercall发生的次数
    __u32 pad;
};

struct hc_key {
    __u64 nr;
    pid_t pid;
    __u32 vcpu_id;
};

struct process {
    __u32 pid;
    __u32 tid;
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
    IRQ_INJECT,
    HYPERCALL,
    IOCTL,
} event_type;

struct common_event {
    struct process process;
    __u64 time;

    // 成员特定于每个事件类型的数据
    union {
        struct {
            __u64 dur_hlt_ns;
            bool waited;
            __u32 vcpu_id;
            bool valid;
            // VCPU_WAKEUP 特有成员
        } vcpu_wakeup_data;

        struct {
            __u32 reason_number;
            __u64 duration_ns;
            __u32 count;
            __u32 total;
            // EXIT 特有成员
        } exit_data;

        struct {
            bool grow;
            __u32 new;
            __u32 old;
            __u32 vcpu_id;
            // HALT_POLL 特有成员
        } halt_poll_data;

        struct {
            __u64 npages;
            __u64 userspace_addr;
            __u64 rel_gfn;
            __u64 gfn;
            __u16 slot_id;
            // MARK_PAGE_DIRTY 特有成员
        } mark_page_dirty_data;

        struct {
            __u64 delay;
            __u64 error_code;
            __u64 addr;
            __u64 pfn;
            __u64 hva;
            __u32 count;
            __u16 memslot_id;
            // PAGE_FAULT 特有成员
        } page_fault_data;

        struct {
            __u64 delay;
            __u32 ret;
            __u32 irqchip_type;
            /*pic*/
            __u16 chip;
            __u32 pin;
            __u16 elcr;
            __u16 imr;
            /*ioapic*/
            __u64 ioapic_bits;
            __u32 irq_nr;
            /*msi*/
            __u64 address;
            __u64 data;
            // IRQCHIP 特有成员
        } irqchip_data;

        struct {
            __u64 delay;
            bool soft;
            __u32 irq_nr;
            __u32 vcpu_id;
            __u64 injections;
            // IRQ_INJECT 特有成员
        } irq_inject_data;

        struct {
            __u64 hc_nr;
            __u64 a0;
            __u64 a1;
            __u64 a2;
            __u64 a3;
            __u64 hypercalls;
            __u32 vcpu_id;
            // HYPERCALL 特有成员
        } hypercall_data;
    };
};

#endif /* __KVM_WATCHER_H */