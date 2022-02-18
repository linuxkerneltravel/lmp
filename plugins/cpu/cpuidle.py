#!/usr/bin/env python3

from __future__ import print_function
from bcc import BPF
from time import sleep
import argparse

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/cpuidle.h>

enum idle_flag {
    IDLE_NOP,
    IDLE_HLT,
    IDLE_STATE,
    IDLE_NR
};

typedef struct cpu_key {
    u32     cpu;
} cpu_key_t;

typedef struct cpu_value {
    enum idle_flag flag;
    char name[CPUIDLE_NAME_LEN];
    u64 start_time;
} cpu_value_t;

typedef struct state_info {
    cpu_key_t cpu;
    char name[CPUIDLE_NAME_LEN];
} state_info_t;

BPF_HASH(idle_start, cpu_key_t, cpu_value_t);
BPF_HASH(idle_nop, cpu_key_t, u64);
BPF_HASH(idle_hlt, cpu_key_t, u64);
BPF_HASH(idle_state, state_info_t, u64);

// kernel_function : cpu_idle_poll
int do_idle_nop() {
    cpu_key_t key = {};
    cpu_value_t value = {};

    key.cpu = bpf_get_smp_processor_id();

    value.flag = IDLE_NOP;
    value.start_time = bpf_ktime_get_ns();

    idle_start.update(&key, &value);

    return 0;
}

// kernel_function : default_idle_call
int do_idle_hlt() {
    cpu_key_t key = {};
    cpu_value_t value = {};

    key.cpu = bpf_get_smp_processor_id();

    value.flag = IDLE_HLT;
    value.start_time = bpf_ktime_get_ns();

    idle_start.update(&key, &value);

    return 0;
}

// kernel_function : cpuidle_enter_state
int do_idle_state(struct pt_regs *ctx, struct cpuidle_state *target_state) {
    if (target_state == NULL) {
        return 0;
    }

    cpu_key_t key = {};
    cpu_value_t value = {};

    key.cpu = bpf_get_smp_processor_id();
    value.flag = IDLE_STATE;
    bpf_probe_read_kernel(&value.name, sizeof(value.name), target_state->name);
    value.start_time = bpf_ktime_get_ns();

    idle_start.update(&key, &value);

    return 0;
}

// kernel_function : schedule_idle
int do_idle_exit() {
    cpu_key_t key = {};
    cpu_value_t *valuep;
    u64 delta;

    key.cpu = bpf_get_smp_processor_id();

    valuep = idle_start.lookup(&key);
    if (valuep == 0) {
        return 0;
    }

    delta = bpf_ktime_get_ns() - valuep->start_time;
    
    if (valuep->flag == IDLE_NOP) {
        idle_nop.increment(key, delta);
    } else if (valuep->flag == IDLE_HLT) {
        idle_hlt.increment(key, delta);
    } else {
        state_info_t state = {};

        state.cpu = key;
        bpf_probe_read_kernel(&state.name, sizeof(state.name), valuep->name);

        idle_state.increment(state, delta);
    }

    idle_start.delete(&key);

    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="cpu_idle_poll", fn_name="do_idle_nop")
b.attach_kprobe(event="default_idle_call", fn_name="do_idle_hlt")
b.attach_kprobe(event="sched_idle_set_state", fn_name="do_idle_state")
b.attach_kprobe(event="schedule_idle", fn_name="do_idle_exit")

idle_nop = b.get_table("idle_nop")
idle_hlt = b.get_table("idle_hlt")
idle_state = b.get_table("idle_state")

while (1):
    sleep(1)
    for k, v in idle_nop.items():
        print(k, v.value)
    for k, v in idle_hlt.items():
        print(k, v.value)
    for k, v in idle_state.items():
        print(k.cpu.cpu, k.name, v.value)

    idle_nop.clear()
    idle_hlt.clear()
    idle_state.clear()

    print("========")
