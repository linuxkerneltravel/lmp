此版本的BCC_sar仍是用BPF实现syscall时间的统计，但是BPF的执行会带来性能上的损失。

在此程序中，sysc时间是纯粹的用tracepoint:sys_enter和tracepoint:sys_exit来实现的计算，具有误差（大概多一个BPF的时间）；

sys包含了所有系统时间，包括用户进程的内核态时间和内核线程的执行时间。

其中，用户进程的内核态时间包含了syscall时间和进入syscall前后的必要时间，以及大约1/2的BPF时间（特指
syscall所涉及的插桩点，因为它是主要的性能点，执行次数最多）

通过用sys - sysc - kthread，可以大致观察到BPF的性能损耗。

ftrace案例在temp_data/trace_syscBPF_loss.txt中，可以查看其中BPF的执行时间来了解BPF会产生多大的性能损失。