#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "time.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

//动态挂载
SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_mm_fault_enter)
{
	 unsigned int pid;
	 u64 current_time;
     pid=bpf_get_current_pid_tgid();//pid

     current_time= bpf_ktime_get_ns()/1000;//挂载前进程时间
     bpf_map_update_elem(&exec_start, &pid, &current_time, BPF_ANY);//更新map元素
    
     //bpf_printk("KPROBE ENTRY pid=%d,comm=%s,state=%d,current_time=%d\n",pid,comm,state,current_time);
     return 0;
}

SEC("kretprobe/handle_mm_fault")
int BPF_KRETPROBE(handle_mm_fault_exit)
{
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();//获取task_struct结构体数据
	struct event *e;
	unsigned int pid;
	u64  *start_ts;
	u64 duration_ns = 0;
    char comm[20];

	/* get PID and TID of exiting thread/process */
	
	pid = bpf_get_current_pid_tgid();

    start_ts=bpf_map_lookup_elem(&exec_start,&pid);
	if (!start_ts)
		return 0;
	duration_ns = bpf_ktime_get_ns()/1000 - *start_ts;//获取系统进程执行时间
    bpf_map_delete_elem(&exec_start,&pid);//删除当前进程pid对应键值对
   //ringbuf提交
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);//malloc
	if (!e)
		return 0;

    e->duration_ns=duration_ns;
    e->pid=pid;
    bpf_get_current_comm(&e->comm,sizeof(e->comm));
    e->state=BPF_CORE_READ(t,__state);
    bpf_ringbuf_submit(e, 0);
	return 0;
}

