# Linux Tracing System浅析 & eBPF开发经验分享

主讲人：杨润青，博士毕业于浙江大学，目前从事网络安全研究，研究方向包括高级威胁检测，攻击溯源与响应。
视频链接：[Linux Tracing System浅析 & eBPF开发经验分享-Linux内核之旅
](https://www.bilibili.com/video/BV17t4y1x7kV?spm_id_from=333.999.0.0)

## 1. 讲座内容简要描述

本次讲座内容分为两部分：

##### 1) Linux Tracing System浅析 

当初学者接触到Linux平台的tracing系统时，常常被各种词语弄得晕头转向：比如 Kprobe，Tracepoint，Linux Auditing subsystem(auditd)，systemtap，LTTng，perf，trace-cmd，eBPF，bpftrace，BCC等等。初学者往往会有以下疑问：这些专业词语是什么意思？它们之间有什么关系？每种tracing技术的优缺点是什么？应该选择哪种技术？为什么eBPF从中脱颖而出，近年来得到广泛关注？

本次讲座尝试从统一的视角来梳理和对比这些技术的异同点，并尝试回答这些问题。

##### 2) eBPF开发经验分享

eBPF目前正在高速发展，很多坑和解决办法缺乏官方文档。本次讲座主要介绍主讲人在eBPF开发实践中经常遇到的问题，包括开发框架的选择，多内核版本兼容性问题，如何为低版本内核生成BTF文件，eBPF验证机制与编译器优化机制的不一致问题，eBPF在ARM架构遇到的问题等等。

## 2. Linux Tracing System浅析

对于Linux Tracing System尤其是目前最火的eBPF技术来说，主要是通过探针技术，实现特定事件的追踪和采样，达到增强内核行为可观测性、优化系统性能、动态监测网络和加固系统安全的目的。
如下图所示，可以将Linux Tracing System细分为三个维度，包括：

* **数据源（内核态）**
提供数据的来源，如常听到的硬件事件、Tracepoint、Kprobe等；

* **Tracing内核框架（内核态）**
负责对接数据源，采集解析发送数据，并为用户态工具提供接口；

* **前端工具/库（用户态）**
对接Tracing内核框架，直接与用户交互，负责采集配置和数据分析，如常用的perf、bpfrace、BCC等。

![avatar](./images/image01_Linux%20Tracing%20System%E7%BB%86%E5%88%86%E4%B8%BA%E4%B8%89%E4%B8%AA%E7%BB%B4%E5%BA%A6.png)

下面将从这三个维度自下而上地对Linux Tracing System进行梳理和分析。

### 2.1　数据源（内核态）

如下图所示，从数据提供方的角度来看，数据源可以分成硬件探针、软件探针（可细分为动态探针以及静态探针），也就是获取底层数据源的方式和手段。

顾名思义，硬件探针技术就是通过在硬件设备上（比如芯片）插入探针，捕获硬件层次行为；而软件探针技术则是通过软件的方式插入探针，捕获软件层次的行为。这些探针技术负责提供数据，上层的Tracing工具和框架则基于这些探针技术来采集数据，并对数据进一步整理、分析、和展现给用户。

![avatar](./images/image02_%E6%95%B0%E6%8D%AE%E6%BA%90.png)

#### 2.1.1 硬件探针

硬件探针是在硬件层次上实现的，如CPU有执行流水线，那厂商便可以在CPU芯片上加入一个探针，在执行jmp或者call的时候进行计数。

##### 1) HPC: Hardware Performance Counter

HPC是CPU硬件提供的一种常见的数据源，如下图所示，它能够监控CPU级别的事件，比如执行的指令数、跳转指令数、Cache Miss等等,被广泛应用于性能调试（Vtune, Perf）、攻击检测等。

![avatar](./images/image03_HPC%E5%88%97%E8%A1%A8.png)

对于此类硬件数据，我们通常使用用户态工具perf来进行采集，下图案例便是展示了perf工具采集的gzip程序在运行过程中的CPU周期数（cycles）、执行的指令数(instructions)以及分支指令数（branches）。

![avatar](./images/image04_HPC%E6%95%B0%E6%8D%AE%E6%A1%88%E4%BE%8B.png)

##### 2) LBR: Last Branch Record

LBR是CPU硬件提供的另一种特性，它能够记录每条分支（跳转）指令的源地址和目的地址。通俗来讲就是LBR按照时间顺序把分支信息记录在特定的寄存器组（MSR）中，基于这样的硬件特性，可实现调用栈信息的记录和监控。

如下图所示，执行主程序时会先首先调用到A函数，A函数再调用B函数，B函数最终调用C函数，C函数执行完printf之后返回到B，B再返回A，A再返回main函数。在硬件层面，LBR按照时间顺序将A、B、C依次入栈，当执行到return的时候再从C到A依次出栈。

![avatar](./images/image05_LBR%E6%89%A7%E8%A1%8C.png)

在系统性能优化领域以及调试程序时经常使用的性能分析利器：火焰图（Flame Graph）也可以基于LBR生成数据。比如在软件无法获取到较为准确的调用栈信息的时候，“`--call-graph lbr`”参数便是利用硬件的特性来采集调用栈生成火焰图。

如下图所示，使用命令`perf record -F 99 -a --call-graph lbr`即可得到完整直观的火焰图数据。

![avatar](./images/image06_%E7%81%AB%E7%84%B0%E5%9B%BE%E6%95%B0%E6%8D%AE.png)

硬件探针的优势很明显，它相较于软件的方式而言性能更好，但缺点是数据过于底层，和用户态在理解上存在语义的鸿沟，如何缩短之间的鸿沟在未来是一个值得重点研究的方向。

#### 2.1.2 软件探针

首先下图为一个静态探针的示例，它使用了trace-cmd命令通过追踪探测点sched_process_exec来监控进程执行二进制文件的行为：

![avatar](./images/image07_%E9%9D%99%E6%80%81%E6%8E%A2%E9%92%88%E7%9A%84%E7%A4%BA%E4%BE%8B.png)

下图是一个动态探针的示例，它输出了和上述静态探针一致的追踪信息：

![avatar](./images/image08_%E5%8A%A8%E6%80%81%E6%8E%A2%E9%92%88%E7%9A%84%E7%A4%BA%E4%BE%8B.png)

可以看出静态探针和动态探针在功能上没有太大的区别，下面将从原理上来回答二者的区别以及优缺点。

##### 1) 静态探针

静态内核探针指的是在内核运行之前，在内核源代码或者二进制中插入预先设置好的钩子函数，内核运行时触发生效的探针方案。
Tracepoint是一种典型的静态探针，它通过在内核源代码中插入预先定义的静态钩子函数来实现内核行为的监控。简单地来看，大家可以把Tracepoint的原理等同于调试程序时加入的printf函数。
下图展示了2012年，内核引入sched_process_exec 追踪点时的commit。可以看到，首先用TRACE_EVENT宏定义了新增Tracepoint的名字和参数等信息，然后在内核函数exec_binprm的源代码中加入了钩子函数trace_sched_process_exec。每当程序执行二进制时，都会触发exec_binprm函数，继而触发trace_sched_process_exec钩子函数。Tracing工具和框架将自定义的函数挂载到该钩子函数上，来采集程序执行行为日志。

![avatar](./images/image09_%E5%86%85%E6%A0%B8%E5%BC%95%E5%85%A5sched_process_exec%20%E8%BF%BD%E8%B8%AA%E7%82%B9%E6%97%B6%E7%9A%84commit.png)

* **静态探针的优点：**

1. 稳定：因为是人工插入的，所以内核开发者会负责维护该函数的稳定性；
2. 性能好：直接在源码中插入。

* **静态探针的缺点：**

1. 每当生成新的Tracepoint都需要修改内核代码，向上游提交补丁；
2. 内核支持的静态探针数量有限。

#### 2)	动态探针

有了静态探针，为什么还需要动态探针呢？主要原因是静态探针需要预埋，而且支持的数量有限，而动态探针就是为了解决这个问题，它能够支持Hook几乎所有的内核函数。
Kprobe是一个典型的动态探针，在内核运行时，Kprobe技术将需要监控的内核函数的指令动态替换，使得该函数的控制流跳转到用户自定义的处理函数上。当内核执行到该监控函数时，相应的用户自定义处理函数被执行，然后继续执行正常的代码路径。
如下就是一个内核系统调用的实现示意图，Kprobe首先会将左边运行时的两行代码替换为右边的jump code，于是每次代码运行到此处都会跳转执行Hijack function，即钩子函数，这时我们便可以在钩子函数中实现想要的功能如系统调用数的统计和参数的获取。而在钩子函数执行完之后便会回去执行原本要继续执行的代码，这样设计是为了保证原本的功能不被破坏。

![avatar](./images/image10_%E5%8A%A8%E6%80%81%E6%8E%A2%E9%92%88%E7%A4%BA%E6%84%8F%E5%9B%BE.png)

* **动态探针的优点：**
不需要预埋，可以Hook几乎所有的内核函数。
* **动态探针的缺点：**
1. 不稳定：由于没有人维护，函数的变更、编译器的优化等都可能导致采集程序的失效；
2. 为了保证程序的安全性，与之相对应的代价是性能相对较差。

#### 3) 动静态结合的探针

静态探针性能好，但支持的数量有限，动态探针支持的数量多，但不稳定、性能相对较差，那么是否存在一种技术，能同时兼顾静态探针性能好和动态探针灵活性强的优势呢？答案是动静态结合的探针方案。
在实际应用中，Ftrace不是指一种特定的工具，更像是一套框架，其中包含了各种技术。例如Ftrace的Function Tracer技术，它可以采集指定函数的调用栈信息，即谁调用了这个函数。下图为使用trace-cmd命令采集函数__audit_inode的调用栈信息。

![avatar](./images/image11_trace-cmd%E5%91%BD%E4%BB%A4%E9%87%87%E9%9B%86%E5%87%BD%E6%95%B0__audit_inode%E7%9A%84%E8%B0%83%E7%94%A8%E6%A0%88%E4%BF%A1%E6%81%AF.png)

Function Hooks是Ftracce引入的一套动静态结合的探针方案，这里称为Compile time hooks+Dynamic Function Tracer。如下图所示，静态指的是它通过gcc编译器，在内核编译阶段，在内核函数的入口处插入了预留的特定指令nop（在未开启tracer时以保证不影响原本的性能）。动态指的是当内核运行时，它会将动态地将预留的特定指令nop替换为跳转指令（call ftrace_caller)，使得内核函数的控制流跳转到用户自定义函数上，达到数据监控的目的。

![avatar](./images/image12_Compile%20time%20hooks%2BDynamic%20Function%20Tracer.png)

此外，Ftrace的Funcgraph Tracer技术能够找到特定函数调用了哪些子函数，下图便是监控了内核函数exec_binprm的所有子函数调用关系。

![avatar](./images/image13_%E7%9B%91%E6%8E%A7%E4%BA%86%E5%86%85%E6%A0%B8%E5%87%BD%E6%95%B0exec_binprm%E7%9A%84%E6%89%80%E6%9C%89%E5%AD%90%E5%87%BD%E6%95%B0%E8%B0%83%E7%94%A8%E5%85%B3%E7%B3%BB.png)

它和Function Tracer的主要区别就是不仅要在被监控函数进入的地方插入动态监测点，同时还要在函数返回的位置插入，其原因是要向监控子函数的调用和退出，只监控入口是不够的。需要注意的一点是，这里不光会在当前函数的进出口放置在动态监测点，子函数的进出口也需要放置，这样才能保证监控到所有函数。

![avatar](./images/image14_%E5%AD%90%E5%87%BD%E6%95%B0%E7%9A%84%E8%BF%9B%E5%87%BA%E5%8F%A3%E4%B9%9F%E9%9C%80%E8%A6%81%E6%94%BE%E7%BD%AE.png)

上面分析完各种动态和静态探针的方案和优缺点后，从开发者代码多功能可控的角度出发，建议优先使用静态探针方案。

### 2.2 Tracing内核框架（内核态）

实际上很多Tracing框架可以对接底层多个数据源，如下图所示，Ftrace对接了Tracepoint、Kprobe以及自己的Function hooks功能，eBPF除此之外还对接了硬件的HPC。
![avatar](./images/image15_Ftrace%E5%AF%B9%E6%8E%A5%E4%BA%86Tracepoint%E3%80%81Kprobe%E4%BB%A5%E5%8F%8A%E8%87%AA%E5%B7%B1%E7%9A%84Function%20hooks%E5%8A%9F%E8%83%BD.png)

在图中可以看到一个特立独行的Auditing Subsystem，它不仅有自己的前端工具，还拥有自己的数据源，它所使用的数据源是通过在内核的系统调用和文件源代码中插入自定义的hook函数来实现系统调用和文件行为的监控，相比于其他的技术而言Audit hooks性能非常差。

#### 2.2.1 Linux Tracing System 发展历程

* 2004年4月，Linux Auditing subsystem(auditd)被引入内核2.6.6-rc1；
* 2005年4月，Kprobe被引入内核2.6.11.7；
* 2006年，LTng发布（至今没有合入内核）；
* 2008年10月，Kernel Tracepoint 被引入内核（v2.6.28）；
* 2008年，Ftrace被引入内核（包括compile time function hooks）；
* 2009年，perf被引入内核；
* 2009年，SystemTap发布（至今没有合入内核）；
* 2014年，Alexei Starovoitov将eBPF引入内核。

#### 2.2.2 Linux Tracing 框架方案对比

下图为从四个维度来对当前主流的几种Tracing框架进行对比。

![avatar](./images/image16_Tracing%E6%A1%86%E6%9E%B6%E8%BF%9B%E8%A1%8C%E5%AF%B9%E6%AF%94.png)

eBPF的优势：
* 稳定：通过验证器，防止用户编写的程序导致内核崩溃，而且相较于内核模块，eBPF的稳定性更容易被产品线接受；
* 免安装：eBPF内置于linux内核，无需安装额外以来；
* 内核编程：支持开发者插入自定义的代码逻辑（包括数据采集、分析和过滤）到内核中运行；
  
## 3. eBPF开发框架

### 3.1 eBPF基础架构

eBPF程序分为两部分: 用户态和内核态代码。

##### 1) eBPF内核代码:

这个代码首先需要经过编译器（比如LLVM）编译成eBPF字节码，然后字节码会被加载到内核执行。所以 这部分代码理论上用什么语言编写都可以，只要编译器支持将该语言编译为eBPF字节码即可。
目前绝大多数工具都是用的C语言来编写eBPF内核代码，包括BCC。
bpftrace提供了一种易用的脚本语言来帮助用户快速高效的使用eBPF功能，其背后的原理还是利用LLVM 将脚本转为eBPF字节码。

##### 2) eBPF用户态代码: 

这部分代码负责将eBPF内核程序加载到内核，与eBPF MAP交互，以及接收eBPF内核程序发送出来的数据。这个功能的本质上是通过Linux OS提供的syscall（bpf syscall + perf_event_open syscall）完成的，因此这 部分代码你可以用任何语言实现。比如BCC使用python，libbpf使用c或者c++，TRACEE使用Go等等。

![avatar](./images/image17_eBPF%E7%94%A8%E6%88%B7%E6%80%81%E4%BB%A3%E7%A0%81.png)

### 3.2 eBPF数据源

如下图所示，eBPF可以对接的数据源有：
* 动态的数据源可分为用户态的uprobe和内核态的kprobe；
* 静态的Tracepoint点；
* perf-event可以对接到硬件的如cycle数和指令数等。

![avatar](./images/image18_eBPF%E5%8F%AF%E4%BB%A5%E5%AF%B9%E6%8E%A5%E7%9A%84%E6%95%B0%E6%8D%AE%E6%BA%90.png)

### 3.3 eBPF框架的发展历程

* 2014年9月 引入了bpf() syscall，将eBPF引入用户态空间。
  * 自带迷你libbpf库，简单对bpf()进行了封装，功能是将eBPF字节码加载到内核。
  * 2015年2月份 Kernel 3.19 引入bpf_load.c/h文件，对上述迷你libbpf库再进行封装，功能是将eBPF elf二进制文件加载到内核（目前已过时，不建议使用）。
* 2015年4月 BCC项目创建，提供了eBPF一站式编程。
  * 创建之初，基于上述迷你libbpf库来加载eBPF字节码。
  * 提供了Python接口。
* 2015年11月 Kernel 4.3 引入标准库 libbpf
  * 该标准库由Huawei 2012 OS内核实验室的王楠提交。
* 2018年为解决BCC的缺陷，CO-RE（Compile Once， Run Everywhere）的想法被提出并实现。
  * 最后达成共识：libbpf + BTF + CO-RE代表了eBPF的未来，BCC底层实现逐步转向libbpf。

### 3.4 eBPF可移植性痛点和解决方案

#### 3.4.1 技术痛点

##### 1）eBPF可移植性差：
在内核版本A上编译的eBPF程序，无法直接在另外一个内核版本B上运行。造成可以执行差的根本原因在于eBPF程序访问的内核数据结构(内存空间）是不稳定的，经常随内核版本更迭而变化。
##### 2）BCC通过在部署机器上动态编译eBPF源代码来解决可移植性问题：
目前使用BCC的方案通过在部署机器上动态编译eBPF源代码可以来解决移植性问题。每一次eBPF程序运行都需要进行一次编译，而且需要在部署机器上按照上百兆大小的依赖，如编译器和头文件Clang/LLVM + Linux headers等。同时在Clang/LLVM编译过程中需要消耗大量的资源（CPU/内存），对业务性能也会造成很大影响。

#### 3.4.2 解决方案-（CO-RE Compile Once，Run Everywhere）

##### 1）CO-RE实现原理：
* BTF：将内核数据结构信息高效压缩和存储（相比于DWARF，可达到超过100倍的 压缩比）；
* LLVM/Clang编译器：编译eBPF代码的时候记录下relocation相关的信息；
* Libbpf：基于BTF和编译器提供的信息，动态relocate数据结构。
其中BTF为重要组成部分，Linux Kernel 5.2及以上版本自带BTF文件，低版本需要手动移植。
通过分析内核源码，可以发现BTF文件的生成并不需要改动内核，只依赖：
* 带有debug info的vmlinux image
* pahole
* LLVM
这意味着，我们可以自己为低版本内核生产BTF文件，以此让低内核版本支持CORE。

##### 2）为低版本内核生成BTF文件
**准备工作：**
* 安装pahole软件（1.16+）
  * https://git.kernel.org/pub/scm/devel/pahole/pahole.git
* 安装LLVM（11+）
  * 获取目标低版本内核的vmlinux文件（带有debug info），文件保存在{vmlinux_file_path}
  * 通过源下载
  * 比如对于CentOS，通过yum install kernel-debuginfo可以下载vmlinux
  * 源码编译内核，获取vmlinux
 
**生成BTF：** 
* 利用pahole在vmlinux文件中生成BTF信息，执行以下命令：
  * pahole -J {vmlinux_file_path}
* 将BTF信息单独输出到新文件{BTF_file_path}，执行以下命令：
  * llvm-objcopy --only-section=.BTF --set-section-flags .BTF=alloc,readonly --strip- all {vmlinux_file_path} {BTF_file_path}
* 去除非必要的符号信息，降低BTF文件的大小，得到最终的BTF文件（大小约2~3MB）：
  * strip -x {BTF_file_path}
