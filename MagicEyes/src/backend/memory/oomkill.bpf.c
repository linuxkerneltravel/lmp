/**
* 追踪系统中oom_kill_process的调用次数
*/
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Jingxiang Zeng
// Copyright (c) 2022 Krisztian Fekete
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "oomkill.h"

// char LICENSE[] SEC("license") = "GPL";
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
    struct data_t *data;
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if (!data)
        return 0;

    data->fpid = bpf_get_current_pid_tgid() >> 32;
    data->tpid = BPF_CORE_READ(oc, chosen, tgid);
    data->pages = BPF_CORE_READ(oc, totalpages);
    bpf_get_current_comm(&data->fcomm, sizeof(data->fcomm));
    bpf_probe_read_kernel(&data->tcomm, sizeof(data->tcomm), BPF_CORE_READ(oc, chosen, comm));

    bpf_ringbuf_submit(data, 0);

    return 0;
}



