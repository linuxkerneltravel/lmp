## preempt_time工具介绍

​	preempt_time,统计每次系统中抢占调度所用的时间。

### 原理分析

​	使用 btf raw tracepoint监控内核中的每次调度事件： 

```c
SEC("tp_btf/sched_switch")
```

​	btf raw tracepoint 跟常规 raw tracepoint 有一个 最主要的区别是： btf 版本可以直接在 ebpf 程序中访问内核内存， 不需要像常规 raw tracepoint 一样需要借助类似 `bpf_core_read` 或 `bpf_probe_read_kernel` 这样 的辅助函数才能访问内核内存。

```c
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next) 
```

​	该事件为我们提供了关于抢占的参数preempt，我们可以通过判断preempt的值来决定是否记录本次调度信息。

​	另一挂载点为kprobe：finish_task_switch，即本次调度切换完成进行收尾工作的函数，在此时通过ebpf map与之前记录的调度信息做差，即可得到本次抢占调度的时间：

```c
SEC("kprobe/finish_task_switch") 
```

### 输出效果

可以获取到抢占进程的`pid`与进程名，以及被抢占进程的`pid`，和本次抢占时间，单位纳秒

```
COMM           prev_pid next_pid duration_ns
node             14221   2589     3014       
kworker/u256:1   15144   13516    1277       
node             14221   2589     3115       
kworker/u256:1   15144   13516    1125       
kworker/u256:1   15144   13516    974        
node             14221   2589     2560       
kworker/u256:1   15144   13516    1132       
node             14221   2589     2717       
kworker/u256:1   15144   13516    1206       
kworker/u256:1   15144   13516    1131       
node             14221   2589     3355   
```
