#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
//#include <linux/arch/x86/include/asm/ptrace.h>
//#include <asm/ptrace.h>
//#include <linux/sched.h>
#include "sys.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile long long unsigned int forks_addr = 0;
#define PF_IDLE			0x00000002	/* I am an IDLE thread */
#define PF_KTHREAD		0x00200000	/* I am a kernel thread */

//环形缓冲区；
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");
BPF_ARRAY(start,int,u64,1);
// 计数表格，第0项为所统计fork数，第1项为进程切换数,
BPF_ARRAY(countMap,int,u64,3);
// 记录开始的时间
BPF_ARRAY(procStartTime,pid_t,u64,4096);
// 储存运行队列rq的全局变量
BPF_ARRAY(rq_map,u32,struct rq,1);
BPF_PERCPU_ARRAY(runqlen, u32, int,1);
/*记录软中断开始时间*/
BPF_PERCPU_ARRAY(softirqCpuEnterTime, u32, u64,4096);
/*软中断结束时间*/
BPF_ARRAY(softirqLastTime,u32,u64,1);
// 记录开始的时间
BPF_PERCPU_HASH(irq_cpu_enter_start, u32, u64,8192);
//记录上次中断时间
BPF_ARRAY(irq_Last_time,u32,u64,1);
// 储存cpu进入空闲的起始时间
BPF_ARRAY(idleStart,u32,u64,128);
// 储存cpu进入空闲的持续时间
BPF_ARRAY(idleLastTime,u32,u64,1);
BPF_ARRAY(kt_LastTime,u32,u64,1);
BPF_ARRAY(ut_LastTime,u32,u64,1);
BPF_ARRAY(tick_user,u32,u64,1);
BPF_ARRAY(symAddr,u32,u64,1);

// 统计fork数
SEC("kprobe/finish_task_switch")
//SEC("kprobe/finish_task_switch.isra.0")
int kprobe__finish_task_switch(struct pt_regs *ctx)
{
    u32 key = 0;
    u64 val, *valp = NULL;
    unsigned long total_forks;

    if(forks_addr !=0){
        valp = (u64 *)forks_addr;
        bpf_probe_read_kernel(&total_forks, sizeof(unsigned long), valp);
        key = 1;
        val = total_forks;
        bpf_map_update_elem(&countMap,&key,&val,BPF_ANY);
    }
    return 0;
}

//获取进程切换数;
SEC("tracepoint/sched/sched_switch")//静态挂载点
int trace_sched_switch2(struct cswch_args *info) {
	//从参数info中获取上一个(prev)和下一个(next)进程的进程号
	pid_t prev = info->prev_pid, next = info->next_pid;//定义上一个、下一个进程的进程号
	
	// 只有当上一个进程和下一个进程不相同时才执行以下操作，相同则代表是同一个进程
	if (prev != next) {
		u32 key = 0;
		u64 *valp, delta, cur;
		struct task_struct *ts;

		// 将下一个进程的进程号赋给pid
		pid_t pid = next;
		u64 time = bpf_ktime_get_ns();//获取当前时间，ns；

		// Step1: 记录next进程的起始时间
		bpf_map_update_elem(&procStartTime,&pid,&time,BPF_ANY);//上传当前时间到start map中
		//procStartTime.update(&pid, &time);//python

		// Step2: Syscall时间处理
		// record_sysc(time, prev, next);

		// Step3: UserMode时间处理
		// record_user(time, prev, next);

		// Step4: 记录上下文切换的总次数
		valp =  bpf_map_lookup_elem(&countMap,&key);
		if (!valp) {
			// 没有找到表项
			u64 initval = 1;
			bpf_map_update_elem(&countMap,&key,&initval,BPF_ANY);//初始化切换次数到countMap中
		}
		else *valp += 1;
		//bpf_map_update_elem(&countMap,&key,&valp,BPF_ANY);//上传当前切换次数到countMap中
	}

	return 0;
}

SEC("kprobe/finish_task_switch")
int BPF_KPROBE(finish_task_switch,struct task_struct *prev){
	pid_t pid=BPF_CORE_READ(prev,pid);
	u64 *val, time = bpf_ktime_get_ns();
	u64 delta;
	// Step1: 记录内核进程（非IDLE）运行时间
	if ((BPF_CORE_READ(prev,flags) & PF_KTHREAD) && pid!= 0) {
		val = bpf_map_lookup_elem(&procStartTime, &pid);
		if (val) {
			u32 key = 0;
			delta = time - *val;
			val = bpf_map_lookup_elem(&kt_LastTime, &key);
			if (val) *val += delta;
			else bpf_map_update_elem(&kt_LastTime, &key, &delta, BPF_ANY);
		}// Step2: 记录用户进程的运行时间
	}else if (!(BPF_CORE_READ(prev,flags) & PF_KTHREAD) && !(BPF_CORE_READ(prev,flags) &PF_IDLE)) {
		val = bpf_map_lookup_elem(&procStartTime, &pid);
		if (val) {
		u32 key = 0;
 		delta = (time - *val)/1000;//us
 		val = bpf_map_lookup_elem(&ut_LastTime, &key);
		if (val) *val += delta;
 		else bpf_map_update_elem(&ut_LastTime, &key, &delta, BPF_ANY);
		}
	} 
	return 0;

}


static __always_inline int user_mode(struct pt_regs *regs)
{
	#ifdef CONFIG_X86_32
		return ((regs->cs & SEGMENT_RPL_MASK) | (regs->flags & X86_VM_MASK)) >= USER_RPL;
	#else
		return !!(regs->cs & 3);
	#endif
}
// 两个CPU各自会产生一个调用，这正好方便我们使用
SEC("perf_event")
int tick_update(struct pt_regs *ctx) {

	// bpf_trace_printk("cs_rpl = %x\n", ctx->cs & 3);
	u32 key = 0;
	u64 val, *valp;

	// 记录用户态时间，直接从头文件arch/x86/include/asm/ptrace.h中引用
	if (user_mode(ctx)) {
		u64 initval = 1;
		valp = bpf_map_lookup_elem(&tick_user, &key);
		if (valp) *valp += 1;
		else bpf_map_update_elem(&tick_user, &key, &initval, BPF_ANY);
	}

	unsigned long total_forks;

	// if(forks_addr !=0){
    //     valp = (u64 *)forks_addr;
    //     bpf_probe_read_kernel(&total_forks, sizeof(unsigned long), valp);
    //     key = 1;
    //     val = total_forks;
    //     bpf_map_update_elem(&countMap,&key,&val,BPF_ANY);
    // }

	valp = bpf_map_lookup_elem(&symAddr, &key);
	if (valp) {
		void *addr = (void *)(*valp);
		if (addr > 0) {
			bpf_probe_read_kernel(&total_forks, sizeof(unsigned long), addr);
			key = 1;
			val = total_forks;
			bpf_map_update_elem(&countMap, &key, &val, BPF_ANY);
		}
	}

	return 0;
}
