#include "vmlinux.h"
#include <bpf/bpf_helpers.h>		//包含了BPF 辅助函数
#include <bpf/bpf_tracing.h>
#include "cs_delay.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义数组映射
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, u64);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/schedule")
int BPF_KPROBE(schedule)
{
	u64 t1;
	t1 = bpf_ktime_get_ns()/1000;	//bpf_ktime_get_ns返回自系统启动以来所经过的时间(以纳秒为单位)。不包括系统挂起的时间。
	int key=0;
	bpf_map_update_elem(&start,&key,&t1,BPF_ANY);

	return 0;
}

SEC("kretprobe/schedule")
int BPF_KRETPROBE(schedule_exit)
{	
	u64 t2 = bpf_ktime_get_ns()/1000;
	u64 t1,delay;
	int key = 0;
	u64 *val = bpf_map_lookup_elem(&start,&key);
	if (val != 0) 
	{
        	t1 = *val;
        	delay = t2 - t1;
	}else{
		return 0;
	}
	bpf_map_delete_elem(&start, &key);
	
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;	
	
	e->t1=t1;
	e->t2=t2;
	e->delay=delay;
	
	/* 成功地将其提交到用户空间进行后期处理 */
	bpf_ringbuf_submit(e, 0);
	
	return 0;
}
