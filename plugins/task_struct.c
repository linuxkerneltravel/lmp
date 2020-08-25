#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/rtc.h>

// 定义输出数据的类型
struct data_t {
	//进程管理部分字段 -> task_struct
//以下是 tag：
    u32 pid;					//进程的pid号                  ok
    char comm[TASK_COMM_LEN];	//进程的应用程序名字             ok
//以下是 field：    
    long state;                 //进程状态                      ok
    int on_cpu;                 //在哪个cpu上运行
    int normal_prio;            //进程的动态优先级               ok
    u64 utime;                  //进程用户态耗费的时间            ok
    u64 stime;                  //进程内核态耗费的时间            ok
    unsigned long nvcsw;        //进程上下文切换次数，自愿
    unsigned long nivcsw;       //进程上下文切换次数，非自愿
    //long tv_nsec;				//
    u64 sum_exec_runtime;       //已经运行的时间总和              ok
    u64 vruntime;				//虚拟运行时间                   ok

    //内存管理部分字段 -> mm_struct


};

//数据输出的通道
BPF_PERF_OUTPUT(events);

int offcpu(struct pt_regs *ctx) {
    //实例化一个自定义结构体
    struct data_t data = {};

    //声明 BPF 程序需要用到的数据结构
    struct task_struct *task = NULL;
    struct sched_entity *my_q;
    struct timespec tt;

    data.pid = bpf_get_current_pid_tgid();
    if(data.pid == PID) 
    {
        //获取进程描述符
        task = (struct task_struct *)bpf_get_current_task();

        //data.ts = bpf_ktime_get_ns();
        //获取进程管理部分数据
        //tt = current_kernel_time();
        //data.tv_nsec = tt.tv_nsec;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        data.state = task->state;
        data.on_cpu = task->on_cpu;
        data.normal_prio = task->normal_prio;
        data.utime = task->utime;
        data.stime = task->stime;
        data.nvcsw = task->nvcsw;
        data.nivcsw = task->nivcsw;
        //获取进程调度实体
        my_q = (struct sched_entity *)&task->se;
        data.sum_exec_runtime = my_q->sum_exec_runtime;
        data.vruntime = my_q->vruntime;


        //获取进程的内存管理信息
        //pass

        //传送数据到用户空间
        events.perf_submit(ctx, &data, sizeof(data));
    }

    return 0;
}