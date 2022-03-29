+++
title = "插件：cpu/taskswitch.py"
description = "针对插件：plugins/cpu/taskswitch.py 的分析"
weight = 5

+++

## 插件说明
插件地址： plugins/cpu/taskswitch.py

## 插件功能说明
统计进程调度时上下文切换的时间开销。

## 插件代码解读

- 挂载点：

```c
b.attach_kretprobe(event="pick_next_task_fair", fn_name="switch_start")
b.attach_kretprobe(event="pick_next_task_idle", fn_name="switch_start")
b.attach_kretprobe(event="pick_next_task_rt", fn_name="switch_start")
b.attach_kretprobe(event="pick_next_task_dl", fn_name="switch_start")
b.attach_kretprobe(event="pick_next_task_stop", fn_name="switch_start")
    
b.attach_kprobe(event="finish_task_switch", fn_name="switch_end")
```

每个调度器类sched_class都提供一个`pick_next_task`函数用以在就绪队列中选择一个最优的进程来等待调度。所以使用kretprobe挂载eBPF程序在各个调度器类的pick_next_task完成时，记录一个时间点，作为开始时间。在`context_switch`最后，会调用`finish_task_switch`进行返回，所以使用kprobe挂载eBPF程序在此记录为结束时间。开始时间与结束时间的时间差即为上下文切换的时间差。

- BPF映射

```c
struct key_t {
    u32 cpu;
    u32 pid;
    u32 tgid;
};

BPF_HASH(start, struct key_t);
BPF_HASH(dist, struct key_t);
```

`start`以`struct key_t`为key，用来存储开始时间。

`dist`以`struct key_t`为key，用来存储时间差。

- 时间记录
```c
int switch_start(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;

    start.update(&key, &ts);
    return 0;
}

int switch_end(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    struct key_t key;
    u64 *value;
    u64 delta;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = prev->pid;
    key.tgid = prev->tgid;

    value = start.lookup(&key);

    if (value == 0) {
        return 0;
    }

    delta = ts - *value;
    start.delete(&key);
    dist.increment(key, delta);

    return 0;
}
```
`switch_start`中获取当前的cpu、pid、tgid作为key存储在`start`表中。`switch_end`中利用进入`finish_task_switch`的参数`struct task_struct *prev`获得上一进程的信息作为key在`start`表中查找开始时间，并获取当前时间减去开始时间得到时间差，存储到`dist`表中。

## 插件使用

### 后台运行方式
直接命令行运行 python 的方式来执行该 eBPF 程序。

```python
cd lmp
sudo python3 plugins/cpu/taskswitch.py
```

![image-20220218171950725](images/image-20220218171950725.png)

### 和Grafana联动

```
SELECT "pid", "duration"  FROM "taskswitch" 
```

![image-20220218174444770](images/image-20220218174444770.png)

## 插件运行版本
### 插件适用版本
Ubuntu 18.04 (4.15.0-generic)及之后版本
### 已经测试过的版本

Ubuntu 18.04 (4.15.0-generic)

Ubuntu 20.04（5.4.0-77-generic）

