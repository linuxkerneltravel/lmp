# LMP：Linux Microscopy

## 项目目标

1. 帮助运维人员更全面地了解系统实时运行状态
2. 希望通过BPF技术来探测系统性能数据
3. 能够通过web形式展示性能数据



## 技术要点

第一阶段要点：

1. goweb框架gin、golang操作influxdb
2. BPF技术提取性能数据
3. 前端实现

（实现图中逻辑）



ToDo...



![](https://wx2.sinaimg.cn/mw690/005yyrljly1gdfu8xhbabj31880qck3b.jpg)



## BPF当前进展

/bpf：这部分提取来进程管理部分的指标，分别是过去一秒内的调度延迟、软中断时间、硬中断时间、特定进程的oncpu时间、就绪队列长度。

/task_struct：这是一个提取进程描述符task_struct字段的小例子，数据存储在influxdb中，前端使用Grafana可视化工具展示数据



