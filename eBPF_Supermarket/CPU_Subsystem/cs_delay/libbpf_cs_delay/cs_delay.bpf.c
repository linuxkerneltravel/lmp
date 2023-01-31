#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_tracing.h>
#include "cs_delay.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义哈希映射
struct {
	__uint(type, BPF_MAP_TYPE_HASH);	//BPF_MAP_TYPE_HASH用途：真正意义上的 map 数据类型，如果 key 值为整数以外的类型必须使用
	__uint(max_entries, 1);
	__type(key, pid_t);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/schedule")
int BPF_KPROBE(schedule)
{
	pid_t pid;
	u64 ts;
	
	pid = bpf_get_current_pid_tgid();
	ts = bpf_ktime_get_ns()/1000;	//bpf_ktime_get_ns返回自系统启动以来所经过的时间(以纳秒为单位)。不包括系统挂起的时间。
	bpf_map_update_elem(&start,&pid,&ts,BPF_ANY);
	
	return 0;	
}

SEC("kretprobe/schedule")
int BPF_KRETPROBE(schedule_exit)
{	
	u64 t2 = bpf_ktime_get_ns()/1000;
	u64 t1,delay;
	pid_t pid = bpf_get_current_pid_tgid();
	u64 *val = bpf_map_lookup_elem(&start,&pid);		//查询完后，下一步直接对返回值进行判断，以防止后续出现这样的报错：R7 invalid mem access 'map_value_or_null'
	if (val != 0) 
	{
        t1 = *val;
        delay = t2 - t1;
	}else{
		return 0;
	}
	bpf_map_delete_elem(&start, &pid);
	
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;	
	
	e->pid = pid;
	e->t1=t1;
	e->t2=t2;
	e->delay=delay;
	
	/* 成功地将其提交到用户空间进行后期处理 */
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}
