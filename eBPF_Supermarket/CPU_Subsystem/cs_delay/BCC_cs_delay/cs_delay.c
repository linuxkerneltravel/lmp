#include <uapi/linux/ptrace.h>

BPF_ARRAY(start, u64,1);
BPF_HISTOGRAM(dist);

int do_entry(struct pt_regs *ctx)	//pt_regs结构定义了在系统调用或其他内核条目期间将寄存器存储在内核堆栈上的方式
{
	u64 t1= bpf_ktime_get_ns()/1000;	//bpf_ktime_get_ns返回自系统启动以来所经过的时间(以纳秒为单位)。不包括系统挂起的时间
	int key=0;
	start.update(&key,&t1);
	
	return 0;
}

int do_return(struct pt_regs *ctx)
{
	u64 t2= bpf_ktime_get_ns()/1000;
	u64 *tsp, delay;
	
	int key=0;
	tsp = start.lookup(&key);
	
	if (tsp != 0)
   	{
        	delay = t2 - *tsp;
        	start.delete(&key);
        	dist.increment(bpf_log2l(delay));
	}
	
	return 0;
}
