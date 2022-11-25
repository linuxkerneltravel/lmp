from bcc import BPF
from time import sleep

b=BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include "myrq.h"
/*
struct rq {
	raw_spinlock_t lock;
	unsigned int nr_running;
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
	unsigned int numa_migrate_on;
    unsigned long		last_load_update_tick;
	long unsigned int last_blocked_load_update_tick;
	unsigned int has_blocked_load;

    int cpu;
};*/

struct myrq{
    unsigned int nr_running;
    unsigned int nr_numa_running;
	long long nr_uninterruptible;
    int cpu;
};

BPF_ARRAY(map_rq,struct rq,1);
BPF_HASH(my_rq,struct myrq,u64,1024);

int get_rqlen(struct pt_regs *ctx){
    struct rq * p_rq = 0;
    u64 zero = 0;
    u32 key = 0;
    struct myrq mrq = {};
    int i = 0;
    
    p_rq = (struct rq *)map_rq.lookup(&key);
     if (!p_rq) { 
		return 0;
	}

    bpf_probe_read_kernel(p_rq,sizeof(struct rq),(void *)PT_REGS_PARM1(ctx));

    mrq.nr_running = p_rq->nr_running;
    mrq.nr_numa_running = p_rq->nr_numa_running;
    mrq.nr_uninterruptible = (long long)(p_rq->nr_uninterruptible);
    mrq.cpu = p_rq->cpu;

    my_rq.lookup_or_try_init(&mrq,&zero);

    return 0;
}

""")


b.attach_kprobe(event="update_rq_clock",fn_name="get_rqlen")

sum2=sum1=0
exp=1884
time = 0
while(1):
    # for i in range(0, 10): sleep(0.1)
    time+=1
    sleep(1)
    averun=aveunrun=0
    rq_list = [ [0] * 3 for i in range(16)]

    # hash table need clear every second
    for j,v in b["my_rq"].items():
        rq_list[j.cpu][0]+=1
        rq_list[j.cpu][1] += j.nr_running
        rq_list[j.cpu][2] += j.nr_uninterruptible

    for i in range(len(rq_list)):
        if(rq_list[i][0]==0): break
        averun += rq_list[i][1]/rq_list[i][0]
        aveunrun += rq_list[i][2]/rq_list[i][0]

    print(rq_list)
    if(aveunrun < 0):
        aveunrun = 0

    sum=averun+aveunrun
    sum2=sum1*exp+sum*(2048-exp)
    print("%d"%time)
    sum2 = sum2 / 2048
    for j,v in b["my_rq"].items():
        print(" cpu : %3d, nr_running : %3d  ,nr_uninterruptible: %5lu" % ( j.cpu,j.nr_running,j.nr_uninterruptible, ))

    print("loadavg: %f  ,sum1: %f  ,sum: %f ,averun %d, aveunrun %d"%(sum2,sum1,sum,averun,aveunrun))
    b["my_rq"].clear()
    print("---------------------------------------------------------------------------")
    sum1=sum2

