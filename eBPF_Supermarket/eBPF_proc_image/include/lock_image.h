#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

struct proc_lockptr{
    int pid;
    long long unsigned int lock_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, u64);
} proc_lock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, u64);
} proc_unlock SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct proc_lockptr);
	__type(value, struct event);
} lock SEC(".maps");

static int record_lock_enter(void *ctx,int type,void *__lock,int target_pid,void *events)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 lock_ptr = (u64)__lock;
        struct proc_lockptr proc_lockptr = {};
        struct event *event;
        
	if(bpf_map_update_elem(&proc_lock, &pid, &lock_ptr, BPF_ANY))
            return 0;

        proc_lockptr.pid = pid;
        proc_lockptr.lock_ptr = lock_ptr;
        
        
        if (bpf_map_update_elem(&lock, &proc_lockptr, &empty_event, BPF_NOEXIST))
            return 0;

        event = bpf_map_lookup_elem(&lock, &proc_lockptr);
        if (!event)
            return 0;

        event->type = type;
        event->pid = pid;
        event->ppid = (pid_t)BPF_CORE_READ(current, real_parent, pid);
        event->cpu_id = bpf_get_smp_processor_id();
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        event->start = bpf_ktime_get_ns();
        event->enable_char_args = false;
        event->args_count = 1;
        event->ctx_args[0] = lock_ptr;

        output_event(ctx,event,events);
    }

    return 0;
}

static int record_lock_exit(void *ctx,int ret,int target_pid,void *events)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 *lock_ptr;
        struct proc_lockptr proc_lockptr = {};
        struct event *event;

        lock_ptr = bpf_map_lookup_elem(&proc_lock, &pid);
        if(!lock_ptr)
            return 0;

        proc_lockptr.pid = pid;
        proc_lockptr.lock_ptr = *lock_ptr;

        event = bpf_map_lookup_elem(&lock, &proc_lockptr);
        if(!event)
            return 0;

        event->type ++;
        event->exit = bpf_ktime_get_ns();
        event->retval = ret;

        output_event(ctx,event,events);

        event->start = event->exit;

        bpf_map_delete_elem(&proc_lock, &pid);
    }

    return 0;
}

static int record_unlock_enter(void *__lock,int target_pid)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 lock_ptr = (u64)__lock;
        if(bpf_map_update_elem(&proc_unlock, &pid, &lock_ptr, BPF_ANY))
            return 0;
    }

    return 0;
}

static int record_unlock_exit(void *ctx,int target_pid,void *events)
{
    pid_t pid = target_pid;
    struct task_struct *current = (struct task_struct *)bpf_get_current_task();

    if(BPF_CORE_READ(current,pid) == pid)
    {
        u64 *lock_ptr;
        struct proc_lockptr proc_lockptr = {};
        struct event *event;
        
        lock_ptr = bpf_map_lookup_elem(&proc_unlock, &pid);
        if(!lock_ptr)
            return 0;

        proc_lockptr.pid = pid;
        proc_lockptr.lock_ptr = *lock_ptr;

        event = bpf_map_lookup_elem(&lock, &proc_lockptr);
        if(!event)
            return 0;
        event->type ++;
        event->exit = bpf_ktime_get_ns();

        output_event(ctx,event,events);

        bpf_map_delete_elem(&proc_unlock, &pid);

        bpf_map_delete_elem(&lock, &proc_lockptr);
    }

    return 0;
}
