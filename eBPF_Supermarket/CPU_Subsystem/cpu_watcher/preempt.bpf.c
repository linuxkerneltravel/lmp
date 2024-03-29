#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "cpu_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TIF_NEED_RESCHED 3

// 记录时间戳
BPF_HASH(preemptTime, pid_t, u64, 4096);

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next) {
    u64 start_time = bpf_ktime_get_ns();
    pid_t prev_pid = BPF_CORE_READ(prev, pid);
    
    if (preempt) {
        bpf_map_update_elem(&preemptTime, &prev_pid, &start_time, BPF_ANY);
    }
    
    // 下面的代码被注释掉，因为我们使用`preempt`参数判断是否需要记录时间戳
    // if (prev->thread_info.flags & TIF_NEED_RESCHED) {
    //     bpf_map_update_elem(&preemptTime, &prev_pid, &start_time, BPF_ANY);
    // }
    
    return 0;
}

SEC("kprobe/finish_task_switch") 
int BPF_KPROBE(finish_task_switch, struct task_struct *prev) {
    u64 end_time = bpf_ktime_get_ns();
    pid_t pid = BPF_CORE_READ(prev, pid);
    u64 *val;
    val = bpf_map_lookup_elem(&preemptTime, &pid);
    if (val) {
        u64 delta = end_time - *val;
        struct preempt_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!e) {
            return 0;
        }   
        e->prev_pid = pid;
        e->next_pid = bpf_get_current_pid_tgid() >> 32;
        e->duration = delta;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
        bpf_map_delete_elem(&preemptTime, &pid);    
    }
    
    return 0;
}
