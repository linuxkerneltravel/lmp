+++
title = "插件：cpu/cpuutilize.py"
description = "针对插件：plugins/cpu/cpuutilize.py 的分析"
weight = 5
+++

## 插件说明
插件地址： plugins/cpu/cpuutilize.py

## 插件功能说明
计算CPU利用率，并将结果写入influxdb数据库。

## 插件代码解读

通过`b.attach_kprobe(event="finish_task_switch", fn_name="pick_start")`将BPF程序关联到内核`finish_task_switch`函数。

具体的BPF程序（部分）：

```c
BPF_HASH(dist, u32, struct time_t);
int pick_start(struct pt_regs *ctx, struct task_struct *prev)
{
    u64 ts = bpf_ktime_get_ns();
    delta = ts - *value;
    time_prev = dist.lookup(&cpu);
    if (time_prev == 0) {
        cpu_time.total = 0;
        cpu_time.idle = 0;
    }else {
        cpu_time = *time_prev;
    }
    cpu_time.total += delta;
    if (pid == 0) {
        cpu_time.idle += delta;
    }
    dist.update(&cpu, &cpu_time);
}
```

数据保存在了哈希表`dist`中，当执行完这段BPF程序后可以通过`dist = b.get_table("dist")`将数据从映射空间中读取出来。之后利用这些时间点采样的数据计算CPU利用率：
$$
1-(idle2-idle1)/(cpu2-cpu1)
$$

```python
for k, v in dist.items():
    cpu[k.value] = 1.0 * (v.total - v.idle) / v.total * 100
    test_data = lmp_data(
        datetime.now().isoformat(), 'glob', cpu[k.value])
    print(cpu[k.value])
    write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
    dist.clear()
```

其中存储的数据结构`data_struct`为：

```python
data_struct = {"measurement": 'cpuutilize',
               "time": [],
               "tags": ['glob', ],
               "fields": ['perce']}
```

之后调用`db_modules`中实现的`write2db`写入数据库

```python
write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)
```

## 插件使用

### 后台运行方式
直接命令行运行 python 的方式来执行该 eBPF 程序。若在插件所在目录直接执行该插件，需要添加引用路径：

```python
import sys
sys.path.append('../common/')
```

![image-20211229224046062](images/python.png)

### web运行方式

![image-20211231122234057](images/web.png)

### 和Grafana联动

通过网页页面运行 eBPF 程序。

查询语句：

```
SELECT "perce" FROM "cpuutilize" 
```

![image-20211229224121966](images/grafana.png)

## 插件运行版本
### 插件适用版本
Ubuntu 18.04 (4.15.0-generic)及之后版本
### 已经测试过的版本

Ubuntu 18.04 (4.15.0-generic)

Ubuntu 20.04（5.4.0-77-generic）

## 总结

本插件通过在`finish_task_switch`时进行采样，计算出cpu时间和idle时间，进而计算cpu利用率。

## 额外说明

暂无