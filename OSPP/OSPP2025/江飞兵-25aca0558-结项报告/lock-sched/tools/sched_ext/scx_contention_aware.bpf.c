// scx_contention_aware.bpf.c
/*
 * A contention-aware scheduler based on scx_simple.
 * It monitors lock contention and boosts the priority of lock holders.
 */
#include <scx/common.bpf.h> // 使用官方环境的头文件

char _license[] SEC("license") = "GPL";

// --- Base scheduler variables from scx_simple ---
const volatile bool fifo_sched;
static u64 vtime_now;
UEI_DEFINE(uei);
#define SHARED_DSQ 0

// --- Maps for lock contention tracking ---
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 10240);
} lock_owners SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 10240);
} active_mutex_lock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 10240);
} waiters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 10240);
} contended_owners SEC(".maps");

// --- Tracepoint struct: This should be in vmlinux.h, but define defensively ---
struct sched_wakeup_args {
    unsigned long long unused;
    char comm[16];
    pid_t pid;
    int prio;
    int target_cpu;
};

// --- Helper functions for lock tracking ---
static __always_inline void increment_waiter_count(u32 owner_tid) {
    u32 *count = bpf_map_lookup_elem(&contended_owners, &owner_tid);
    u32 new_count = (count) ? (*count + 1) : 1;
    bpf_map_update_elem(&contended_owners, &owner_tid, &new_count, BPF_ANY);
}

static __always_inline void decrement_waiter_count(u32 owner_tid) {
    u32 *count = bpf_map_lookup_elem(&contended_owners, &owner_tid);
    if (count) {
        if (*count <= 1) {
            bpf_map_delete_elem(&contended_owners, &owner_tid);
        } else {
            u32 new_count = *count - 1;
            bpf_map_update_elem(&contended_owners, &owner_tid, &new_count, BPF_ANY);
        }
    }
}

// --- kprobes and tracepoints for lock monitoring ---
SEC("kprobe/mutex_lock")
int handle_mutex_lock_enter(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 lock_addr;
    bpf_probe_read_kernel(&lock_addr, sizeof(lock_addr), &ctx->di);
    bpf_map_update_elem(&active_mutex_lock, &tid, &lock_addr, BPF_ANY);
    return 0;
}

SEC("kretprobe/mutex_lock")
int handle_mutex_lock_exit(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 tgid_tid = bpf_get_current_pid_tgid();
    u64 *lock_addr_ptr = bpf_map_lookup_elem(&active_mutex_lock, &tid);
    if (!lock_addr_ptr) return 0;
    long ret;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ax);
    if (ret == 0) bpf_map_update_elem(&lock_owners, lock_addr_ptr, &tgid_tid, BPF_ANY);
    bpf_map_delete_elem(&active_mutex_lock, &tid);
    return 0;
}

SEC("kprobe/mutex_unlock")
int handle_mutex_unlock(struct pt_regs *ctx) {
    u64 lock_addr;
    bpf_probe_read_kernel(&lock_addr, sizeof(lock_addr), &ctx->di);
    bpf_map_delete_elem(&lock_owners, &lock_addr);
    return 0;
}

SEC("kprobe/__mutex_lock_slowpath")
int handle_mutex_contended(struct pt_regs *ctx) {
    u64 lock_addr;
    bpf_probe_read_kernel(&lock_addr, sizeof(lock_addr), &ctx->di);
    u32 waiter_tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 *owner_tgid_tid_ptr = bpf_map_lookup_elem(&lock_owners, &lock_addr);
    if (!owner_tgid_tid_ptr) return 0;
    u32 owner_tid = *owner_tgid_tid_ptr & 0xFFFFFFFF;
    bpf_map_update_elem(&waiters, &waiter_tid, &owner_tid, BPF_ANY);
    increment_waiter_count(owner_tid);
    return 0;
}

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

SEC("tp/syscalls/sys_enter_futex")
int handle_futex_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 uaddr = (u64)ctx->args[0];
    int op = (int)ctx->args[1] & 127;
    u64 current_tgid_tid = bpf_get_current_pid_tgid();
    u32 current_tid = current_tgid_tid & 0xFFFFFFFF;

    if (op == FUTEX_WAIT) {
        u64 *owner_tgid_tid_ptr = bpf_map_lookup_elem(&lock_owners, &uaddr);
        if (!owner_tgid_tid_ptr) return 0;
        u32 owner_tid = *owner_tgid_tid_ptr & 0xFFFFFFFF;
        bpf_map_update_elem(&waiters, &current_tid, &owner_tid, BPF_ANY);
        increment_waiter_count(owner_tid);
    } else if (op == FUTEX_WAKE) {
        bpf_map_update_elem(&lock_owners, &uaddr, &current_tgid_tid, BPF_ANY);
    }
    return 0;
}

SEC("tp/sched/sched_wakeup")
int handle_sched_wakeup(struct sched_wakeup_args *ctx) {
    u32 woken_tid = ctx->pid;
    u32 *owner_tid_ptr = bpf_map_lookup_elem(&waiters, &woken_tid);
    if (!owner_tid_ptr) return 0;
    decrement_waiter_count(*owner_tid_ptr);
    bpf_map_delete_elem(&waiters, &woken_tid);
    return 0;
}

// --- MODIFIED sched_ext operations ---
#define BOOST_FACTOR (SCX_SLICE_DFL / 4)

s32 BPF_STRUCT_OPS(ops_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
	bool is_idle = false;
	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	return cpu;
}

void BPF_STRUCT_OPS(ops_enqueue, struct task_struct *p, u64 enq_flags) {
	u64 vtime = p->scx.dsq_vtime;
    u32 tid = p->pid;
    u32 *waiter_count = bpf_map_lookup_elem(&contended_owners, &tid);

    if (waiter_count && *waiter_count > 0) {
        // 限制最大奖励，比如不超过2个标准时间片
        u64 max_boost = 16 ; // 最多奖励 8 个等待者的量
        u64 vtime_boost = *waiter_count * BOOST_FACTOR;

        if (vtime_boost > max_boost) {
            vtime_boost = max_boost;
        }
        // vtime_boost = vtime_boost / 2 ; // 奖励力度减半
        // 减少任务的虚拟运行时间，相当于提升优先级
        if (vtime > vtime_boost)
            vtime -= vtime_boost;
        else
            vtime = 0;
    }
    // 如果一个任务的 vtime 远远落后于当前时间，把它拉近一点
    // 比如落后超过 1000ms (1000 * 1,000,000 ns)
    // if (time_after(vtime, vtime_now + 1000000000)) {
    //     vtime = vtime_now; // 直接把它拉到当前时间
    // }

	if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
		vtime = vtime_now - SCX_SLICE_DFL;
	scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
}

void BPF_STRUCT_OPS(ops_dispatch, s32 cpu, struct task_struct *prev) {
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(ops_running, struct task_struct *p) {
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(ops_stopping, struct task_struct *p, bool runnable) {
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(ops_enable, struct task_struct *p) {
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(ops_init) {
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(ops_exit, struct scx_exit_info *ei) {
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(ops,
	       .select_cpu	= (void *)ops_select_cpu,
	       .enqueue		= (void *)ops_enqueue,
	       .dispatch	= (void *)ops_dispatch,
	       .running		= (void *)ops_running,
	       .stopping	= (void *)ops_stopping,
	       .enable		= (void *)ops_enable,
	       .init		= (void *)ops_init,
               .exit        = (void *)ops_exit,
	       .name		= "scx_contention_aware",
           .timeout_ms  = 30000 );