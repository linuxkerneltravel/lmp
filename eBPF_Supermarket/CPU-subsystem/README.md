## CPU子系统指标捕获例程

### 0. 介绍

本目录是由一系列捕获CPU子系统指标（主要是调度指标）的例程组成的。

bpftrace_application 是一些 Bpftrace 构建的例程，需要预装 bpftrace，其特点是代码简单，能很快上手，缺点是不能支撑高复杂性的 eBPF 应用。

其余以 go_ 开头的各个文件夹是用 go语言 + eBPF 构建的eBPF例程，使用了开源的cilium/eBPF库，可以支撑高复杂性、模块化的 eBPF 应用。

### 1. 准备工作

环境：Ubuntu 20.04, 内核版本 5.13.0-30-generic

注：由于 eBPF 的 kprobe 逻辑与内核数据结构定义高度相关，而现在 BTF 的应用（可消除不同内核版本间数据结构的不兼容）还不是很成熟，因此在使用此例程前，需首先适配内核版本。

软件：

* go SDK（安装cilium库）

* llvm
* bpftrace

### 2. bpftrace应用

runqlen_percpu.c: 打印每个CPU的runqlen分布情况。使用了kprobe，挂载点是update_rq_clock.

runqlen_se.c: 打印每个CPU的 CFS 调度的队列长度分布情况。使用了kprobe，挂载点是update_rq_clock.

使用方法：

```shell
cd bpftrace_application
sudo ./runqlen_percpu.c
```

### 3. go_* 应用

**go_migrate_info**: 以事件的形式打印CPU间进程迁移的情况。每次迁移都打印一条信息，包括时间戳、进程pid、源CPU、目标CPU、进程优先级。这可用于后期前端开发可视化地显示进程迁移情况。

**go_schedule**: 打印每个CPU的runqlen分布情况。

**go_schedule_uninterruptible**: 打印整个kernel所有处于**不可打断阻塞状态**的任务的数目。

**go_switch_info**：每1s打印现有所有进程的进程切换数。

使用方法：

```shell
cd go_schedule
cd schedule
./run.sh
```

