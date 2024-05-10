#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "cpu_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//记录时间戳；
BPF_ARRAY(start,int,u64,1);
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/schedule")
int BPF_KPROBE(schedule)
{
	u64 t1;
	t1 = bpf_ktime_get_ns()/1000;
	int key =0;
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
			bpf_map_delete_elem(&start, &key);
	}else{
		return 0;
	}
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)	return 0;	
	e->t1=t1;
	e->t2=t2;
	e->delay=delay;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

