+++
title = "插件：cpu/picknext.py"
description = "针对插件：plugins/cpu/picknext.py 的分析"
weight = 5
+++

## 插件说明
插件地址： plugins/cpu/picknext.py

## 插件功能说明
统计CFS调度器pick_next_task_fair选择下一个进程的执行时间。

## 插件代码解读

利用kprobe挂接在内核`pick_next_task_fair`函数
```c
b.attach_kprobe(event="pick_next_task_fair", fn_name="pick_start")
b.attach_kretprobe(event="pick_next_task_fair", fn_name="pick_end")
```
BPF映射：
```c
BPF_HASH(start, struct key_t);
BPF_HASH(dist, struct key_t);
```
分别存储进入的时间和统计的累计时间。

在进入`pick_next_task_fair`函数前，执行了BPF程序中`pick_start`函数：
```c
int pick_start(struct pt_regs *ctx)
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
```
其主要作用为获得当前时间和cpu、pid、tgid等信息，其中cpu、pid、tgid作为哈希表的键，时间作为值。
在退出`pick_next_task_fair`函数时，执行了BPF程序中`pick_end`函数：

```c
int pick_end(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;
    u64 *value;
    u64 delta;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;

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
其主要作用是获取当前时间，并通过键在哈希表start中查找对应的值，相减得到时间差，并累积到哈希表dist中。
## 插件使用

### 后台运行方式
直接命令行运行 python 的方式来执行该 eBPF 程序。

```python
cd lmp
sudo python3 plugins/cpu/picknext.py
```

![image-20220128180136196](images/image-20220128180136196.png)

### web运行方式

![image-20220128180701441](images/image-20220128180701441.png)

### 和Grafana联动

```
SELECT "perce" FROM "cpuutilize" 
```

![image_20220128180234](images/image-20220128180234.png)

## 插件运行版本
### 插件适用版本
Ubuntu 18.04 (4.15.0-generic)及之后版本
### 已经测试过的版本

Ubuntu 18.04 (4.15.0-generic)

Ubuntu 20.04（5.4.0-77-generic）

## 总结

本插件通过kprobe挂载`pick_next_task_fair`函数，得到其执行时间，进而可以分析系统性能。

## 额外说明

暂无