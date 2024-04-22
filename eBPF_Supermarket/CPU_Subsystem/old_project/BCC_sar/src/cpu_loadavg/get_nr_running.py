from bcc import BPF
from time import sleep

b=BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct parm{
    int  num;
};

BPF_ARRAY(my_arr,int,1);
BPF_HASH(my_run,struct parm,u64,1024);
BPF_HASH(my_io,struct parm,u64,1024);

int kretprobe__nr_running(struct pt_regs *ctx){
    u64 key = 0;
    struct parm pa = {};
    pa.num=PT_REGS_RC(ctx);

    my_run.lookup_or_try_init(&pa,&key);

    return 0;
    
}

int kretprobe__nr_iowait(struct pt_regs *ctx){
    u64 key = 0;
    struct parm pa = {};
   pa.num=PT_REGS_RC(ctx);

    my_io.lookup_or_try_init(&pa,&key);

    return 0;
}

int kprobe__show_stat(struct pt_regs *ctx){
    int n = 0;
    int * iq = 0;
    int key = 0;

    iq = (int *)my_arr.lookup(&key);
     if (!iq) { 
		return 0;
	}

    n = *iq;
    my_arr.update(&n,&key);
}
""")

# b.attach_kprobe(event="nr_running",fn_name="get_nr_running")
time = 0
print(b)
while(1):
    time+=1
    sleep(1)
    print("--------------------------------------------")
    print("time:%d"%time)

    print(b["my_arr"][0])
    for j,v in b["my_run"].items():
        print("run:%d"%j.num)

    for j,v in b["my_io"].items():
        print("io:%d"%j.num)

    b["my_run"].clear()
    b["my_io"].clear()
