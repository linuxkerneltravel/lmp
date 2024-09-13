# eBPF多维度性能分析测试方案

## 一、测试准备

​	在本次eBPF性能分析以及测试中，将从多个维度去分析eBPF程序在不同内核版本下以及在不同负载情境下，不同Map类型和挂载点类型的性能差异。

​	首先，我们先在测试之前进行测试的一些必要的准备。

​	使用以下表格来说明本次测试需要的准备：

| 准备项         | 说明                               |
| -------------- | ---------------------------------- |
| 内核版本的选取 | 选取本次测试需要测试的内核版本     |
| 负载环境的选取 | 确定本次测试的负载方案             |
| Map类型的选取  | 确定好本次测试将要测试的Map类型    |
| 挂载点的选取   | 确定好本次测试将要测试的挂载点类型 |
| 测试机配置     | 说明测试机的各项配置               |

### **1.内核版本的选取：**

​	首先，在选取需要测试的Linux内核版本时，考虑两个方面，第一个是在eBPF发展中比较有转折点的内核版本，其次是目前企业应用和日常学习中，大家比较常用的Linux内核版本。首先，以下是eBPF技术在主要内核版本中的发展过程及其引入的功能（主要关注Map和程序类型）：

| 内核版本   | 时间    | 新增功能                                                     |
| ---------- | ------- | ------------------------------------------------------------ |
| Linux 3.18 | 2014.12 | 基础的eBPF Maps引入：最初引入的map类型有`hash map`和`array map` |
| Linux 4.6  | 2016.5  | 引入了`Per-CPU`的哈希表和数组类型                            |
| Linux 4.3  | 2015.11 | 支持了`kprobe`和`tracepoints`                                |
| Linux 4.14 | 2017.11 | 支持eBPF程序附加到`perf events`，用于性能分析和监控          |
| Linux 4.19 | 2018.10 | 引入了环形缓冲区类型的`Ring Buffer Map`                      |
| Linux 5.19 | 2022.7  | 增强了`XDP`和`BPF trampoline`功能，使得动态附加eBPF程序更加高效和灵活 |
| Linux 6.2  | 2023.2  | 增强了对 `fentry` 和 `fexit` 程序类型的支持，使得 eBPF 程序可以更灵活地附加到内核函数的入口和退出点 |
| Linux 6.5  | 2023.8  | 引入了新的机制`bpf_cookie`：允许 eBPF 程序为特定事件分配和管理 `cookie` |

​	通过查阅资料并进行调研，本次测试选取的内核版本为4.19、5.19、6.5三个Linux内核版本来进行分别的测试。

### 2.负载环境的选取：

#### 1.系统负载

​	在本次测试中，会使用负载工具（stress-ng）对整个系统进行加压，比如，对cpu、内存、IO速率进行加压。在这种系统高负载以及在内核版本固定，负载环境固定的情况下，比较不同Map类型和不同挂载点类型在高负载环境下的表现情况。

​	这种设计是考虑eBPF程序在整个系统高负载情况下不同Map类型、不同挂载点类型的性能测试。接下来，还需要测试在eBPF程序本身的高负载环境下，不同Map类型、不同挂载点类型的表现情况。

#### 2.程序内部高负载

​	在本次实验中，也会对eBPF的不同Map进行大量的增删改查操作，来模拟对Map操作的高负载情境。比如，控制eBPF的挂载点相同、内核版本相同、测试环境相同、对不同的Map类型进行相同且大量的增删改查操作，来对比不同Map类型在各种前提都相同，它们的操作在时间性能上存在的差异。

### 3.Map类型的选取：

​	在本次测试中，我们选取的Linux内核版本分别为：4.19、5.19、6.5这三个版本，接下来通过查看内核源码来查看这三个版本分别支持的Map类型，内核路径为：（/include/uapi/linux/bpf.h）

Linux4.19版本支持的Map类型：

```c
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
};//21种
```

Linux5.19版本支持的Map类型：

```c
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE,
	BPF_MAP_TYPE_DEVMAP_HASH,
	BPF_MAP_TYPE_STRUCT_OPS,
	BPF_MAP_TYPE_RINGBUF,
	BPF_MAP_TYPE_INODE_STORAGE,
	BPF_MAP_TYPE_TASK_STORAGE,
	BPF_MAP_TYPE_BLOOM_FILTER,
};//31种
```

Linux6.5版本支持的Map类型：

```c
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_XSKMAP,
	BPF_MAP_TYPE_SOCKHASH,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_CGROUP_STORAGE = BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE,
	BPF_MAP_TYPE_DEVMAP_HASH,
	BPF_MAP_TYPE_STRUCT_OPS,
	BPF_MAP_TYPE_RINGBUF,
	BPF_MAP_TYPE_INODE_STORAGE,
	BPF_MAP_TYPE_TASK_STORAGE,
	BPF_MAP_TYPE_BLOOM_FILTER,
	BPF_MAP_TYPE_USER_RINGBUF,
	BPF_MAP_TYPE_CGRP_STORAGE,
};//34种
```

​	在本次测试中，将对三个内核版本进行分别的分析和测试。

​	目前，将分析并测试常用的Map类型，在Linux4.19内核版本中，将分析并测试以下Map类型：

```c
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
```

​	在Linux5.19内核版本中，将分析并测试常用的以下Map类型：

```c
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_RINGBUF,
```

​	在Linux6.5内核版本中，将分析并测试常用的以下Map类型：

```c
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_RINGBUF,
	BPF_MAP_TYPE_USER_RINGBUF,
```

### 4.挂载点类型的选取：

​	和上面的分析类似，我们先看不同内核版本所支持的挂载点类型：

Linux4.19版本支持的挂载点类型：

```c
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
};//22种
```

Linux5.19版本支持的挂载点类型：

```c
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
	BPF_PROG_TYPE_SYSCALL, 
};//32种
```

Linux6.5版本支持的挂载点类型：

```c
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
	BPF_PROG_TYPE_SYSCALL, 
	BPF_PROG_TYPE_NETFILTER,
};//33种
```

​	在测试这三个不同内核版本的挂载点表现差异时，我们选取常用的挂载点类型，如下所示：

```c
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_SYSCALL, 
```

### 5.测试机的配置

本次测试的主机配置如下所示：

| 名称         | 配置                                                   |
| ------------ | ------------------------------------------------------ |
| CPU          | 13th Gen Intel(R) Core(TM) i9-13900HX   2.20 GHz  16核 |
| 内存         | 16GB                                                   |
| 硬盘大小     | 100GB                                                  |
| 虚拟机       | VMware Workstation 上搭建的ubuntu 22.04.3 LTS          |
| 内核版本     | 4.19、5.19、6.5                                        |
| eBPF开发工具 | libbpf                                                 |

在测试之前，我们需要关闭CPU的P-states和C-states，来确保CPU频率一致性。**P-states** 是处理器的性能状态，用于调整 CPU 的工作频率和电压，以达到性能和功耗的平衡。P-states 允许处理器在不同的性能状态之间切换，以适应当前的计算负载。**C-states** 是处理器的休眠状态，用于降低 CPU 的功耗当其处于空闲状态时。C-states 允许处理器在不使用时进入更深的节能状态，从而减少功耗。

配置如下：

**关闭P-states：**

```shell
GRUB_CMDLINE_LINUX="resume=/dev/mapper/ao_anolis-swap rd.lvm.lv=ao_anolis/root rd.lvm.lv=ao_anolis/swap rhgb quiet"
更改为：
GRUB_CMDLINE_LINUX="resume=/dev/mapper/ao_anolis-swap rd.lvm.lv=ao_anolis/root rd.lvm.lv=ao_anolis/swap rhgb quiet intel_pstate=disable noacpi"
```

**关闭C-states：**

```shell
GRUB_CMDLINE_LINUX="resume=/dev/mapper/ao_anolis-swap rd.lvm.lv=ao_anolis/root rd.lvm.lv=ao_anolis/swap rhgb quiet intel_pstate=disable noacpi"
更改为：
GRUB_CMDLINE_LINUX="resume=/dev/mapper/ao_anolis-swap rd.lvm.lv=ao_anolis/root rd.lvm.lv=ao_anolis/swap rhgb quiet intel_pstate=disable noacpi processor.max_cstate=0"
```

## 二、测试工具引入：

​	在本次测试过程中，会使用以下工具来进行测试：

| 工具               | 工具说明                                                     |
| ------------------ | ------------------------------------------------------------ |
| libbpf             | 使用libbpf工具来进行eBPF程序的编写                           |
| stress-ng          | 通过该工具对系统进行加压，模拟高负载环境                     |
| Visual Studio Code | 使用该开发工具进行虚拟机控制和程序编写                       |
| Python             | 使用Python语言喝Python数据分析的相关库来对测试后的数据进行分析 |
| shell脚本          | 编写shell脚本来自动化测试用例和数据分析的运行                |
| Typora             | 编写测试相关的文档，包括测试分析和测试结果等                 |

## 三、测试计划

| 时间       | 任务                                                         | 产出                                                         |
| ---------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 7.20-8.2   | 详细设计出测试方案，对后面做出详细的规划                     | 输出详细的测试方案                                           |
| Map：      |                                                              |                                                              |
| 8.3-8.9    | 在不同的内核版本下，对Map的各个类型进行详细的理论分析        | 输出详细的Map类型分析报告并给出分析结论                      |
| 8.10-8.16  | 编写测试代码并从时间维度，不同负载的情境下对不同Map进行测试  | 输出详细的测试结果                                           |
| 8.17-8.23  | 完善测试并对结果进行分析                                     | 输出测试结果和理论分析，并不同版本的Map特性，结合理论分析给出一个操作指南 |
| 挂载点：   |                                                              |                                                              |
| 8.24-8.30  | 在不同的内核版本下，对挂载点的各个类型进行详细的理论分析     | 输出详细的挂载点类型分析报告并给出分析结论                   |
| 8.31-9.6   | 编写测试代码并从时间维度，不同负载的情境下对不同挂载点进行测试 | 输出详细的测试结果                                           |
| 9.7-9.13   | 完善测试并对结果进行分析                                     | 输出测试结果和理论分析，并给出不同版本的挂载点特性，结合理论分析给出一个操作指南 |
| 测试补充： |                                                              |                                                              |
| 9.14-9.20  | 通过测试过程中发现的问题和遗漏，再补充一些需要的测试结果     | 初步输出一个项目总体测试文档，并查漏补缺                     |
| 9.21-9.30  | 完善项目总体开发测试文档                                     | 输出最终的测试报告并整理项目代码                             |

## 四、测试方案

​	在测试之前，需要通过查阅资料和阅读内核源码给出一个详细且准确的理论分析报告，然后再通过下述的测试过程和测试结果来验证理论分析的正确性。并且最终给出一个eBPF最佳实践指南。

#### 4.1 Map类型的测试方案：

​	Map类型的测试方案说明了本次测试方案是从时间的角度去分析不同Map类型的差异。

**测试的流程如下图所示：**

![Map测试方案](./images/Map测试方案.png)

对上图进行详细解释：

1.首先，通过上面的分析。我们需要在测试之前确定一些环境因素：

- 确定内核版本，本次测试将从内核版本6.5、5.19、4.19这个顺序来进行测试。
- 确定负载，本次测试将负载定为两大类，分别为：对系统进行加压负载、对Map的操作次数进行设置。
- 确定测试指标，本次测试会对不同Map类型定义相同的空间大小，并且进行相同的操作，来测试这些不同的Map类型在各种环境都确定的情况下，它们在时间维度上的差异。

2.接下来就是编写测试程序，这里会使用libbpf来编写，编写程序的关键点为：

- 根据前面分析的结果，定义选定内核版本需要测试的Map类型。
- 将定义好的所有Map结构体挂载在同一个函数上。
- 在用户态对这些定义的Map进行获取并进行相同次数的相同操作。
- 将每个Map类型的操作时间记录下来。
- 循环上述操作，获取多组测试数据。

3.最后，编写python脚本来对得出的操作时间进行数据分析，并编写shell脚本进行上述所有操作的整合，自动化测试程序：

- 通过测试程序输出的时间数据，进行数据分析。
- 将分析的结果以文件和图表的方式展现出来。
- 输出测试报告并结合理论分析的结果给出一个在Map方面的最佳实践指南。

通过上述的描述，接下来给出一个流程图来说明本次测试的具体过程：

![Map性能测试流程](./images/Map测试流程.png)

测试用例设计：

| 事项             | 内容                                                         |
| ---------------- | ------------------------------------------------------------ |
| 场景             | 在同一系统环境下，针对不同类型的eBPF Map（如HashMap、ArrayMap、LRUHashMap等）进行性能测试。测试内容包括增删改查（CRUD）操作的耗时情况。 |
| 测试目的         | 评估不同类型的eBPF Map在高频率的CRUD操作下的性能表现，特别是针对相同操作次数所需的时间差异。 |
| 负载压力产生方法 | 在ebpf程序中对不同类型的Map设置一个固定的操作次数并记录每次操作的开始和结束时间。确保每个Map类型在相同的条件下测试。 |
| 执行脚本         | map_difference.py                                            |
| 执行方法         | 部署并加载eBPF程序；执行./run_ebpf_and_process.sh脚本；查看分析结果 |
| 与生产环境差异   | 测试环境为隔离的虚拟机，Map的操作次数可能高于生产环境的实际负载，以便突显性能差异。 |
| 指标要求         | 每种Map类型的CRUD操作次数必须相同；相同操作次数下，不同Map类型的耗时差异不应超过预期范围； |
| 测试结果         | 记录每种Map类型的总操作时间，并汇总到报告中，生成柱状图或折线图展示不同Map类型的性能差异。 |
| 测试结果分析     | 分析不同Map类型在CRUD操作下的性能差异，确定性能瓶颈。评估哪种Map类型在高并发场景下表现最优。 |
| 后续Action       | 如果某种Map类型在测试中表现出显著劣势，建议在生产环境中慎用或优化其使用场景。 |


#### 4.2对挂载点类型的测试方案：

未完待续。。。

## 五、测试开发与执行

## 六、测试分析
