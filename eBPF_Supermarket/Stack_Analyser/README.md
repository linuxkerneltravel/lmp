# 1. 功能描述

对操作系统各方面的调用栈进行计数，从中分析程序性能瓶颈。

## 2.1 应用场景及意义

Stack_Analyzer是一个基于eBPF的按照指定时间间隔（默认为5s）来统计涉及特定子系统的进程函数调用栈的性能指标的工具。使用它可以帮助您便捷地查看相关子系统性能损耗最高或者对系统吞吐量影响较大的瓶颈调用栈，直接而具体地设计并进行程序或系统性能上的优化，进而降低对cpu性能的损耗，提高系统吞吐量，以增强车机系统的实时性。

与传统工具相比，Stack_Analyzer可提供指标相关的更细粒度的信息，从以进程为单位监测性能指标深入到了以调用栈为单位，可直接找出性能问题的根源。目前支持的指标如下：

- cpu占用量
- 阻塞时间
- 内存占用大小
- 磁盘/网络IO请求数据量
- 预读取页剩余量

除此之外，本项目设计了一个便于复用的调用栈采集框架，方便监测指标的添加。之后可根据需求添加更多的监测指标。

## 2.2 性能参数及观测意义

采集的指标对主要子系统进行了覆盖，分为以下五个部分：

- on-cpu：进程/线程使用cpu的计数，从而分析出进程的用时最长的调用栈即性能瓶颈
- off-cpu：进程/线程阻塞的时长、阻塞原因（内存分配、主动睡眠、锁竞争等）及调用路径，从而解决出进程执行慢、甚至卡死的问题，提高系统吞吐量
- mem：进程/线程内存占用的大小及分配路径、更进一步可以检测出释放无效指针的问题，从而优化进程的内存分配方式
- io：进程/线程输入/输出的数据量，及相应路径，从而优化进程输入/输出方式
- readahead：进程/线程预读取页面使用量及对应调用栈，从而了解进程读数据的行为特征，进而使用madvise进行优化

为了易于分析调用栈数据，项目加入更多的可视化元素和交互方式，使得画像更加直观、易于理解，对优化程序或系统性能有重要意义。

# 2. 要求

## 2.1 内核要求

- 版本：>= Linux 5.10
- 开启内核选项：
    - kprobes相关选项
        - CONFIG_KPROBES=y
        - CONFIG_KPROBE_EVENT=y
    - uprobe相关选项
        - CONFIG_TRACING_SUPPORT=y
        - CONFIG_FTRACE=y
        - CONFIG_HAVE_REGS_AND_STACK_ACCESS_API=y
        - CONFIG_HAVE_KPROBES_ON_FTRACE=y
        - CONFIG_DYNAMIC_FTRACE_WITH_REGS=y
        - CONFIG_KPROBES_ON_FTRACE=y
    - eBPF相关选项
        - CONFIG_BPF=y
        - CONFIG_BPF_SYSCALL=y
        - CONFIG_BPF_JIT=y
        - CONFIG_HAVE_EBPF_JIT=y
        - CONFIG_BPF_EVENTS=y
        - CONFIG_DEBUG_INFO_BTF=y
        - CONFIG_FTRACE_SYSCALLS=y

## 2.2 数据准确性要求

添加 `-fno-omit-frame-pointer` 选项编译被测程序以保留程序的fp信息，以便监测程序可以通过fp信息回溯被测程序的调用栈。

# 3. 计划安排

- [x] 实时输出功能
- [x] on-cpu 栈采集功能
- [x] off-cpu 栈采集功能
- [x] malloc-free 栈采集功能
- [x] 保存为json文件功能
- [x] 火焰图绘制功能
- [x] io-write栈采集功能
- [x] 加入排序功能
- [x] 收发包栈采集功能
- [ ] 兼容perf数据
- [ ] 栈数据智能分析功能
- [ ] 解决保存数据时卡顿的问题