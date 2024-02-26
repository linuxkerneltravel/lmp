# schedule功能类开发文档

**参考资料：**

- [Linux 的调度延迟 - 原理与观测 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/462728452)
- [linux 内核抢占那些事 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/166032722)

**调度延迟的计算得分两种情况：**

1. 任务因等待 event 进入休眠态（[Voluntary Switch](https://zhuanlan.zhihu.com/p/402423877)），那么就是从被唤醒（"wakeup/wakeup_new" 的时间点），到获得 CPU （任务切换时的 *"next_pid"*）的间隔。
2. 任务因 [Involuntary Switch](https://zhuanlan.zhihu.com/p/402423877) 让出 CPU（任务切换时作为 *"prev_pid"*），到再次获得 CPU （之后的某次任务切换时作为*"next_pid"*）所经历的时间。在这期间，任务始终在 runqueue 上，始终是 runnable 的状态，所以有 "prev_state" 是否为 *TASK_RUNNING* 的判断。

**内核中提供了三个接口来唤醒进程：**

- wake_up_new_task：用来唤醒新进程，fork出来的进程/线程；
- wake_up_process：唤醒处于TASK_NORMAL状态的进程；
- wake_up_state：唤醒指定状态的进程；

后两个接口最终都会调用try_to_wake_up接口：

```
try_to_wake_up-->ttwu_queue-->ttwu_do_active-->ttwu_do_wakeup
```

**相关挂载点：**

```
ttwu_do_wakeup() --> trace_sched_wakeup
wake_up_new_task() --> trace_sched_wakeup_new
__schedule() --> trace_sched_switch
```