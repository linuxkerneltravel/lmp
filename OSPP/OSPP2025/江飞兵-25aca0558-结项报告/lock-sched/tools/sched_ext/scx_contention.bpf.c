/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_contention: A contention-aware scheduler for sched_ext.
 *
 * This scheduler integrates a real-time lock contention sensor with a
 * vtime-based scheduler. It detects when tasks holding locks are being
 * heavily contended and dynamically boosts their priority by extending their
 * execution slice. Once contention subsides, the priority is returned to
 * normal.
 *
 * It is based on scx_simple and retains its vtime/FIFO scheduling modes,
 * but adds the contention-aware logic on top of the vtime mode.
 *
 * Copyright (c) 2024 Your Name <your.email@example.com>
 * Based on scx_simple by Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

// --- 调度器可调参数 (用户态可修改) ---

const volatile u32 high_contention_threshold = 4;
const volatile u64 decay_timeout_ns = 200 * 1000 * 1000; // 200ms
const volatile bool fifo_sched;

// --- 核心数据结构与 BPF Maps ---

#define TASK_COMM_LEN 16

struct contention_event {
    u64 lock_addr;
    u32 owner_tid;
};

struct contention_info {
    u32 waiter_count;
    u64 last_contention_ts;
    // 新增标志位，记录任务是否被提权
    bool boosted;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 10240);
} lock_owners SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct contention_event);
    __uint(max_entries, 10240);
} waiters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct contention_info);
    __uint(max_entries, 10240);
} contended_tasks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10240);
} active_mutex_lock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// --- 锁竞争传感器逻辑 ---

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

static __always_inline void mark_contention(u64 lock_addr, u32 waiter_tid) {
    u64 *owner_tgid_tid_ptr = bpf_map_lookup_elem(&lock_owners, &lock_addr);
    if (!owner_tgid_tid_ptr) return;

    u32 owner_tid = (*owner_tgid_tid_ptr) & 0xFFFFFFFF;
    if (owner_tid == waiter_tid) return;

    struct contention_info *info = bpf_map_lookup_elem(&contended_tasks, &owner_tid);
    if (info) {
        info->waiter_count++;
        info->last_contention_ts = bpf_ktime_get_ns();
    } else {
        struct contention_info new_info = {
            .waiter_count = 1,
            .last_contention_ts = bpf_ktime_get_ns(),
            .boosted = false,
        };
        bpf_map_update_elem(&contended_tasks, &owner_tid, &new_info, BPF_ANY);
    }

    struct contention_event event = { .lock_addr = lock_addr, .owner_tid = owner_tid };
    bpf_map_update_elem(&waiters, &waiter_tid, &event, BPF_ANY);
}

SEC("kprobe/mutex_lock")
int BPF_KPROBE(handle_mutex_lock_enter, struct mutex *lock) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 lock_addr = (u64)lock;
    bpf_map_update_elem(&active_mutex_lock, &tid, &lock_addr, BPF_ANY);
    return 0;
}

SEC("kretprobe/mutex_lock")
int BPF_KRETPROBE(handle_mutex_lock_exit, int ret) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 tgid_tid = bpf_get_current_pid_tgid();
    u64 *lock_addr_ptr = bpf_map_lookup_elem(&active_mutex_lock, &tid);
    if (!lock_addr_ptr) return 0;
    if (ret == 0) {
        bpf_map_update_elem(&lock_owners, lock_addr_ptr, &tgid_tid, BPF_ANY);
    }
    bpf_map_delete_elem(&active_mutex_lock, &tid);
    return 0;
}

SEC("kprobe/mutex_unlock")
int BPF_KPROBE(handle_mutex_unlock, struct mutex *lock) {
    u64 lock_addr = (u64)lock;
    bpf_map_delete_elem(&lock_owners, &lock_addr);
    return 0;
}

SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(handle_mutex_contended, struct mutex *lock) {
    u64 lock_addr = (u64)lock;
    u32 waiter_tid = bpf_get_current_pid_tgid();
    mark_contention(lock_addr, waiter_tid);
    return 0;
}

SEC("tp/syscalls/sys_enter_futex")
int handle_futex_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 uaddr = (u64)ctx->args[0];
    int op = (int)ctx->args[1] & 127;
    u64 current_tgid_tid = bpf_get_current_pid_tgid();
    u32 current_tid = current_tgid_tid;

    if (op == FUTEX_WAIT) {
        mark_contention(uaddr, current_tid);
    } else if (op == FUTEX_WAKE) {
        bpf_map_update_elem(&lock_owners, &uaddr, &current_tgid_tid, BPF_ANY);
    }
    return 0;
}

struct sched_wakeup_args {
    unsigned long long unused;
    char comm[16];
    pid_t pid;
    int prio;
    int target_cpu;
};

SEC("tp/sched/sched_wakeup")
int handle_sched_wakeup(struct sched_wakeup_args *ctx) {
    u32 woken_tid = ctx->pid;
    struct contention_event *event = bpf_map_lookup_elem(&waiters, &woken_tid);
    if (!event) return 0;

    u32 owner_tid = event->owner_tid;
    struct contention_info *info = bpf_map_lookup_elem(&contended_tasks, &owner_tid);
    if (info) {
        if (info->waiter_count > 0) {
            info->waiter_count--;
        }
    }

    bpf_map_delete_elem(&waiters, &woken_tid);
    return 0;
}

// --- 调度器逻辑 ---

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);
} stats SEC(".maps");

static void stat_inc(u32 idx) {
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p) (*cnt_p)++;
}

s32 BPF_STRUCT_OPS(contention_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
	bool is_idle = false;
	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}
	return cpu;
}

void BPF_STRUCT_OPS(contention_enqueue, struct task_struct *p, u64 enq_flags) {
	stat_inc(1);
	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;
		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;
		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
	}
}

void BPF_STRUCT_OPS(contention_dispatch, s32 cpu, struct task_struct *prev) {
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(contention_running, struct task_struct *p) {
	if (fifo_sched) return;
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

// ++++++++++++++++++++++++ 核心修正点 1: stopping 回调 ++++++++++++++++++++++++
void BPF_STRUCT_OPS(contention_stopping, struct task_struct *p, bool runnable) {
	if (fifo_sched) return;
    
    u32 tid = p->pid;
    struct contention_info *info = bpf_map_lookup_elem(&contended_tasks, &tid);

    // 如果任务被标记为提权状态，现在是重置它的最佳时机
    if (info && info->boosted) {
        // 不管任务接下来是继续运行还是睡眠，都重置它的提权状态
        info->boosted = false;
        
        // 如果任务不再可运行（要去睡眠了），就从竞争表中移除
        // 如果它只是被抢占，暂时保留，让 tick 或下次入队时再判断
        if (!runnable) {
            bpf_map_delete_elem(&contended_tasks, &tid);
        }
    }

    // 恢复 vtime 计算
	u64 slice_used = SCX_SLICE_DFL - p->scx.slice;
    // 如果 slice 是 INF, slice_used 会是一个巨大的负数, 会导致 vtime 倒退
    // 这里需要处理这种情况
    if (p->scx.slice > SCX_SLICE_DFL) {
        // 对于被提权的任务，我们只计算它实际运行的时间，而不是slice的差值
        // 但在stopping回调中难以精确获取，所以我们简化为只消耗一个标准slice的vtime
        slice_used = SCX_SLICE_DFL;
    }
	p->scx.dsq_vtime += slice_used * 100 / p->scx.weight;
}
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// ++++++++++++++++++++++++ 核心修正点 2: tick 回调 ++++++++++++++++++++++++++
void BPF_STRUCT_OPS(contention_tick, struct task_struct *p) {
    if (fifo_sched) return;

    u32 tid = p->pid;
    struct contention_info *info = bpf_map_lookup_elem(&contended_tasks, &tid);

    if (!info) {
        return;
    }

    u64 now = bpf_ktime_get_ns();

    // 检查是否需要降级
    if (info->waiter_count == 0 || (now - info->last_contention_ts > decay_timeout_ns)) {
        if (info->boosted) {
            // 标记为不再提权，并立即触发重新调度
            info->boosted = false; 
            p->scx.slice = 0; 
        }
        // 如果waiter_count为0，可以安全移除
        if (info->waiter_count == 0) {
            bpf_map_delete_elem(&contended_tasks, &tid);
        }
        return;
    }

    // 根据等待者数量执行提权策略
    if (info->waiter_count >= high_contention_threshold) {
        // 高度竞争，给予无限时间片
        p->scx.slice = SCX_SLICE_INF;
        info->boosted = true;
    } else if (info->waiter_count > 0) {
        // 轻度竞争，延长一倍时间片
        if (!info->boosted) { // 只有在未提权时才增加，防止无限增长
             p->scx.slice += SCX_SLICE_DFL;
             info->boosted = true;
        }
    }
}
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

void BPF_STRUCT_OPS(contention_enable, struct task_struct *p) {
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(contention_init) {
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(contention_exit, struct scx_exit_info *ei) {
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(contention_ops,
    .select_cpu	= (void *)contention_select_cpu,
    .enqueue	= (void *)contention_enqueue,
    .dispatch	= (void *)contention_dispatch,
    .running	= (void *)contention_running,
    .stopping	= (void *)contention_stopping,
    .tick       = (void *)contention_tick,
    .enable		= (void *)contention_enable,
    .init		= (void *)contention_init,
    .exit		= (void *)contention_exit,
    .name		= "contention"
);