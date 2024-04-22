# proj118-eBPF-based-monitor-for-container
实现一个基于eBPF技术监控容器行为的工具

### 项目描述

容器是一种应用层抽象，用于将代码和依赖资源打包在一起。多个容器可以在同一台机器上运行，共享操作系统内核。这使得容器的隔离性相对较弱，带来安全上的风险，最严重时会导致容器逃逸，严重影响底层基础设施的保密性、完整性和可用性。

**eBPF** 是一个通用执行引擎，能够高效地安全地执行基于系统事件的特定代码，可基于此开发性能分析工具**、**网络数据包过滤**、**系统调用过滤**，**系统观测和分析等诸多场景。eBPF可以由hook机制在系统调用被使用时触发，也可以通过kprobe或uprobe将eBPF程序附在内核/用户程序的任何地方。

这些机制让eBPF的跟踪技术可以有效地感知容器的各项行为，包括但不限于：

- 容器对文件的访问
- 容器对系统的调用
- 容器之间的互访

请基于eBPF技术开发一个监控工具，该工具可以监控容器的行为，并生成报表（如json文件）将各个容器的行为分别记录下来以供分析。

### 所属赛道

2022全国大学生操作系统比赛的“OS功能设计”赛道

### 参赛要求

- 以小组为单位参赛，最多三人一个小组，且小组成员是来自同一所高校的本科生/研究生
- 如学生参加了多个项目，参赛学生选择一个自己参加的项目参与评奖
- 请遵循“2022全国大学生操作系统比赛”的章程和技术方案要求

### 项目导师

- gitee @czrz
- email: chengzeruizhi@huawei.com

### 难度

高

### 参考文档

[https://ebpf.io/what-is-ebpf/](https://ebpf.io/what-is-ebpf/#ebpf-safety)

[https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/html/container_security_guide/linux_capabilities_and_seccomp](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/html/container_security_guide/linux_capabilities_and_seccomp)

### 特征

- 了解eBPF开发工具链，比如BCC、bpftrace等
- 要考虑怎样合理地存储收集的数据

### License

任意开源license都可

### 预期目标

**注意：下面的内容是建议内容，不要求必须全部完成。选择本项目的同学也可与导师联系，提出自己的新想法，如导师认可，可加入预期目标**

1. **第一题：行为感知**

   编写eBPF程序，感知容器的各项行为。

2. **第二题：信息存储**

   在第一题的基础上，令工具可以将采集到的数据以特定的格式保存在本地。

3. **（可选）第三题：权限推荐**

   Seccomp是Linux内核的特性，开发者可以通过seccomp限制容器的行为。capabilities则将进程作为root的权限分成了各项更小的权限，方便调控。这两个特性都有助于保障容器安全，但是因为业务执行的逻辑差异，准确配置权限最小集非常困难。请利用上面开发的监控工具，分析业务容器的行为记录报表，然后基于报表自动推荐精准的权限配置最小集。