// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"   

// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 256 * 1024);
// } events SEC(".maps");

// 全局配置 map
// struct config {
//     __u32 mode;        // 0 = 基础采样, 1 = 深入 CPU, 2 = ...
//     __u32 sample_rate; // 1 表示采样每次事件，>1表示间隔
// };

// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, 1); // 全局只有一个配置
//     __type(key, __u32);
//     __type(value, struct config);
// } config_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16MB
} events SEC(".maps");


// // tracepoint: sched:sched_switch
// SEC("tracepoint/sched/sched_switch")
// int handle_sched_switch(struct trace_event_raw_sched_switch *ctx)
// {
//     __u32 key = 0;
//     struct config *cfg;
//     struct event *e;
//     // 读取全局配置
//     cfg = bpf_map_lookup_elem(&config_map, &key);
//     if (!cfg)
//         return 0;

//     // 根据 sample_rate 做采样控制
//     if (cfg->sample_rate > 1) {
//         __u64 id = bpf_get_smp_processor_id(); // 用 CPU 或 pid 作为 hash 做简单随机采样
//         if ((id % cfg->sample_rate) != 0)
//             return 0;
//     }

//     // 如果 mode == 0 只是基础采样，可在这里加逻辑，比如只记录用户进程切换
//     if (cfg->mode == 0 && (ctx->prev_pid == 0 || ctx->next_pid == 0))
//         return 0; // 忽略 idle


//     e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
//     if (!e)
//         return 0;

//     e->type = EVENT_SCHED_SWITCH;
//     e->sched.prev_pid = ctx->prev_pid;
//     e->sched.next_pid = ctx->next_pid;
//     e->sched.cpu_id   = bpf_get_smp_processor_id();

//     if (bpf_probe_read_kernel_str(&e->sched.prev_comm, sizeof(e->sched.prev_comm), ctx->prev_comm) < 0)
//         __builtin_memcpy(&e->sched.prev_comm, "unknown", 8);

//     if (bpf_probe_read_kernel_str(&e->sched.next_comm, sizeof(e->sched.next_comm), ctx->next_comm) < 0)
//         __builtin_memcpy(&e->sched.next_comm, "unknown", 8);



//     bpf_ringbuf_submit(e, 0);
//     return 0;
// }



SEC("perf_event")
int handle_perf_event(struct bpf_perf_event_data *ctx)
{
    struct event *e;
    u64 id = bpf_get_current_pid_tgid();

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->ts = bpf_ktime_get_ns();
    e->pid = id >> 32;
    e->tgid = id & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 从用户态 attach 时传入的 cookie 读取事件类型
    e->type = bpf_get_attach_cookie(ctx);

    // perf_event 的采样值
    e->val = ctx->sample_period; // 可以换成 ctx->sample_raw 或别的

    bpf_ringbuf_submit(e, 0);
    return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";

