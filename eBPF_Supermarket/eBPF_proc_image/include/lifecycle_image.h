#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

static const struct event empty_event = {};

// 以便于对0号进程进行画像（0号进程是每cpu进程）
struct proc_id{
    int pid;
    int cpu_id;
};

struct proc_oncpu{
    int oncpu_id;
    long long unsigned int oncpu_time;
};

struct proc_offcpu{
    int offcpu_id;
    long long unsigned int offcpu_time;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct proc_id);
	__type(value, struct proc_oncpu);
} oncpu SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct proc_id);
	__type(value, struct proc_offcpu);
} offcpu SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct proc_id);
	__type(value, struct event);
} cpu SEC(".maps");

static void output_event(void *ctx, struct event *event, void *events)
{
	size_t len = EVENT_SIZE(event);
	if (len <= sizeof(*event))
		bpf_perf_event_output(ctx, events, BPF_F_CURRENT_CPU, event, len);
}

static int record_cputime(void *ctx, struct task_struct *prev, struct task_struct *next, pid_t target_pid, int target_cpu_id, void *events)
{
    pid_t next_pid = BPF_CORE_READ(next,pid);
    pid_t prev_pid = BPF_CORE_READ(prev,pid);
    int cpu_id = bpf_get_smp_processor_id();

    // 第一种情况：目标进程从offcpu转变为oncpu
    if((target_pid!= 0 && prev_pid!= target_pid && next_pid==target_pid) || 
        (target_pid==0 && prev_pid!= target_pid && next_pid==target_pid && cpu_id==target_cpu_id))
    {
        u64 oncpu_time = bpf_ktime_get_ns();
        struct proc_id proc_id = {};
        struct proc_offcpu * proc_offcpu;

        proc_id.pid = target_pid;
        proc_id.cpu_id = target_cpu_id;

        proc_offcpu = bpf_map_lookup_elem(&offcpu, &proc_id);
        if(proc_offcpu){
            // 完成一次cpu_event(offcpu)的输出
            struct event *cpu_event;

            if (bpf_map_update_elem(&cpu, &proc_id, &empty_event, BPF_NOEXIST))
		        return 0;

            cpu_event = bpf_map_lookup_elem(&cpu, &proc_id);
            if (!cpu_event)
		        return 0;

            cpu_event->type = 1;
            cpu_event->pid = target_pid;
            cpu_event->ppid = (pid_t)BPF_CORE_READ(next, real_parent, pid);
            cpu_event->cpu_id = cpu_id;
            for(int i = 0; i <= TASK_COMM_LEN - 1; i++){
                cpu_event->comm[i] = BPF_CORE_READ(next,comm[i]);
                if (BPF_CORE_READ(next,comm[i]) == '\0')
                    break;
            }
            cpu_event->start = proc_offcpu->offcpu_time;
            cpu_event->exit = oncpu_time;

            output_event(ctx,cpu_event,events);

            bpf_map_delete_elem(&cpu, &proc_id);
            bpf_map_delete_elem(&offcpu, &proc_id);
        }

        // 记录pro_oncpu
        struct proc_oncpu proc_oncpu = {};

        proc_oncpu.oncpu_id = cpu_id;
        proc_oncpu.oncpu_time = oncpu_time;

        if(bpf_map_update_elem(&oncpu, &proc_id, &proc_oncpu, BPF_ANY))
            return 0;

    // 第二中情况：目标进程从oncpu转变为offcpu
    }else if((target_pid!= 0 && prev_pid==target_pid && next_pid!=target_pid) || 
        (target_pid==0 && prev_pid==target_pid && next_pid!=target_pid && cpu_id==target_cpu_id))
    {
        u64 offcpu_time = bpf_ktime_get_ns();
        struct proc_id proc_id = {};
        struct proc_oncpu * proc_oncpu;

        proc_id.pid = target_pid;
        proc_id.cpu_id = target_cpu_id;

        proc_oncpu = bpf_map_lookup_elem(&oncpu, &proc_id);
        if(proc_oncpu){
            // 完成一次cpu_event(oncpu)的输出
            struct event *cpu_event;

            if (bpf_map_update_elem(&cpu, &proc_id, &empty_event, BPF_NOEXIST))
		        return 0;

            cpu_event = bpf_map_lookup_elem(&cpu, &proc_id);
            if (!cpu_event)
		        return 0;
            
            cpu_event->type = 2;
            cpu_event->pid = target_pid;
            cpu_event->ppid = (pid_t)BPF_CORE_READ(prev, real_parent, pid);
            cpu_event->cpu_id = cpu_id;
            bpf_get_current_comm(&cpu_event->comm, sizeof(cpu_event->comm));
            cpu_event->start = proc_oncpu->oncpu_time;
            cpu_event->exit = offcpu_time;

            output_event(ctx,cpu_event,events);

            bpf_map_delete_elem(&cpu, &proc_id);
            bpf_map_delete_elem(&oncpu, &proc_id);
        }

        // 记录pro_offcpu
        struct proc_offcpu proc_offcpu = {};

        proc_offcpu.offcpu_id = cpu_id;
        proc_offcpu.offcpu_time = offcpu_time;

        if(bpf_map_update_elem(&offcpu, &proc_id, &proc_offcpu, BPF_ANY))
            return 0;
    }

    return 0;
}
