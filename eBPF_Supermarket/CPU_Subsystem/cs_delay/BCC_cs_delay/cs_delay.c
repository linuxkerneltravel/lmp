#include <uapi/linux/ptrace.h>

BPF_ARRAY(start, u64,1);
BPF_HISTOGRAM(dist);

int do_entry(struct pt_regs *ctx)	//pt_regs�ṹ��������ϵͳ���û������ں���Ŀ�ڼ佫�Ĵ����洢���ں˶�ջ�ϵķ�ʽ
{
	u64 t1= bpf_ktime_get_ns()/1000;	//bpf_ktime_get_ns������ϵͳ����������������ʱ��(������Ϊ��λ)��������ϵͳ�����ʱ��
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