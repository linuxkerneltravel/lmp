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

#define PRINT_USAGE_ERR()                                              \
    do {                                                               \
        fprintf(stderr, "Use either the -w, -p, -d, or -e option.\n"); \
        argp_usage(state);                                             \
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

#define RESERVE_RINGBUF_ENTRY(rb, e)                             \
    do {                                                         \
        typeof(e) _tmp = bpf_ringbuf_reserve(rb, sizeof(*e), 0); \
        if (!_tmp)                                               \
            return 0;                                            \
        e = _tmp;                                                \
    } while (0)

#define CHECK_PID(vm_pid)                            \
    unsigned pid = bpf_get_current_pid_tgid() >> 32; \
    if ((vm_pid) < 0 || pid == (vm_pid))

struct process {
    unsigned pid;
    unsigned tid;
    char comm[TASK_COMM_LEN];
};
struct vcpu_wakeup_event {
    struct process process;
    unsigned long long dur_hlt_ns;
    bool waited;
    unsigned long long hlt_time;
};

struct exit_event {
    struct process process;
    unsigned reason_number;
    unsigned long long duration_ns;
    int count;
    int total;
};

struct ExitReason {
    int number;
    const char *name;
};

struct reason_info {
    unsigned long long time;
    unsigned long reason;
    int count;
};

struct halt_poll_ns_event {
    struct process process;
    bool grow;
    unsigned int new;
    unsigned int old;
    unsigned long long time;
};

struct mark_page_dirty_in_slot_event {
    struct process process;
    unsigned long long time;
    unsigned long npages;
    unsigned long userspace_addr;
    unsigned long long rel_gfn;
    unsigned long long gfn;
    short slot_id;
};
#endif /* __KVM_WATCHER_H */