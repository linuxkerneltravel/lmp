#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_tracing.h>
#include "cpu_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义数组映射
BPF_HASH(procStartTime,pid_t,u64,4096);//记录时间戳
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");//环形缓冲区；


SEC("tracepoint/syscalls/sys_enter_execve")//进入系统调用
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx){
	u64 start_time = bpf_ktime_get_ns()/1000;//ms
	pid_t pid = bpf_get_current_pid_tgid() >> 32;//获取到当前进程的pid
	bpf_map_update_elem(&procStartTime,&pid,&start_time,BPF_ANY);
	return 0;

}

SEC("tracepoint/syscalls/sys_exit_execve")//退出系统调用
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx){
	u64 exit_time = bpf_ktime_get_ns()/1000;//ms
	u64 start_time, delay;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;//获取到当前进程的pid
	u64 *val = bpf_map_lookup_elem(&procStartTime, &pid);
	if(val !=0){
		start_time = *val;
		delay = exit_time - start_time;
		bpf_map_delete_elem(&procStartTime, &pid);
	}else{ 
		return 0;
	}

	struct event2 *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;	
	
	e->start_time=start_time;//开始时间
	e->exit_time=exit_time;//结束时间
	e->delay=delay;//时间间隔
	e->pid = pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	/* 成功地将其提交到用户空间进行后期处理 */
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}