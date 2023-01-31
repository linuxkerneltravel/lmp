#include <uapi/linux/ptrace.h>

BPF_HASH(start, u32);
BPF_HISTOGRAM(dist);

int do_entry(struct pt_regs *ctx)	//pt_regs结构定义了在系统调用或其他内核条目期间将寄存器存储在内核堆栈上的方式
{
	u64 t1= bpf_ktime_get_ns()/1000;	//bpf_ktime_get_ns返回自系统启动以来所经过的时间(以纳秒为单位)。不包括系统挂起的时间。;
	u32 pid = bpf_get_current_pid_tgid();
	start.update(&pid,&t1);
	
	return 0;
}

int do_return(struct pt_regs *ctx)
{
	u64 t2= bpf_ktime_get_ns()/1000;
	u32 pid;
	u64 *tsp, delay;
	
	pid = bpf_get_current_pid_tgid();
	tsp = start.lookup(&pid);
	
	if (tsp != 0)
    {
        delay = t2 - *tsp;
        start.delete(&pid);
        dist.increment(bpf_log2l(delay));
	}
	
	return 0;
}
