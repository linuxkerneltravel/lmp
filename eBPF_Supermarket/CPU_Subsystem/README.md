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

### 2. 应用实例介绍

#### 2.1 bpftrace应用

**runqlen_percpu.c**: 打印每个CPU的runqlen分布情况。使用了kprobe，挂载点是update_rq_clock.

**runqlen_se.c**: 打印每个CPU的 CFS 调度的队列长度分布情况。使用了kprobe，挂载点是update_rq_clock.

挂载点说明：update_rq_clock() 函数在内核中的作用是用来更新rq主运行队列的运行时间的，不涉及到具体的某种调度策略（如CFS），因而能够得到通用的调度数据。执行栈是内核的时钟中断函数->update_process_time()->scheduler_tick()->update_rq_clock()，使用update_rq_clock()的优势在于该函数的参数内携带了rq结构体，可直接查阅运行队列rq的数据。执行频率为800~1000Hz，较低，不会影响到内核的运行性能。

使用方法：

```shell
cd bpftrace_application
sudo ./runqlen_percpu.c
```

#### 2.2 go_* 应用

**go_migrate_info**: 以事件的形式打印CPU间进程迁移的情况。每次迁移都打印一条信息，包括时间戳、进程pid、源CPU、目标CPU、进程优先级。这可用于后期前端开发可视化地显示进程迁移情况。

**go_schedule**: 打印每个CPU的runqlen分布情况。

**go_schedule_uninterruptible**: 打印整个kernel所有处于**不可打断阻塞状态**的任务的数目。

**go_switch_info**：每1s打印现有所有进程的进程切换数。

**go_sar**：模仿sar工具，使用eBPF实现其功能。

使用方法：

```shell
cd go_schedule
cd schedule
./run.sh
```

如果没有run.sh脚本，那么，需要手动编译执行以下命令：

```shell
cd go_migrate_info
cd sched_migrate
go generate
sudo go run .
```

**go_sar说明**: 我预先的计划是使用go+cilium来实现sar的功能，但是由于cilium ebpf未实现perf事件挂载点，所以无法实现BPF程序的定时采样，目前我转而使用BCC实现sar的剩余功能。若之后cilium ebpf实现了perf事件挂载点，此程序有可能会更新。目前的效果如下（定时打印）：

```txt
15:35:05 proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms
15:35:06     17      920        3         260        4389        1
15:35:07      1      319        3          82        2039        1
15:35:08      0      508        3         218        2592        0
15:35:09     13      434        2          55        2368        1
15:35:10     11      413        2         105        1906        0
15:35:11      0      370        2          68        1638        1
15:35:12      0      260        2          36        1263        0
15:35:13      0      286        2          59        1450        1
```

其中idle表项目前是不准的，之后会修改。

#### 2.3 BCC_sar

BCC_sar是使用BCC构建的模仿sar进行动态CPU指标监测的程序，其位置在BCC_sar/下。此基于BCC的构建是由之前基于go+cilium的实现转化而来的，用于解决一些go+cilium组合无法解决的问题。目前，此程序能捕获sar工具能捕获的大多数参数。

使用方法:
```sh
定位到./CPU_Subsystem/BCC_sar/src/sar目录
sudo python3 sar.py -h # 获取帮助信息
sudo python3 sar.py -t time # 以时间形式打印各状态占用CPU时间
sudo python3 sar.py -t percent # 以时间占用率形式打印各状态占用CPU时间
sudo python3 sar.py -t percent -i 2 -c 100
# 每隔2s打印一次，持续100次后终止程序
sudo python3 sar.py -t percent -p 1234
# 绑定到1234进程上，显示1234进程的各状态占用率信息
```

以下是sudo python3 sar.py -t time的部分输出：
```txt
  time   proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms
15:40:52     18      616        2          86        3426     2274        1470      108        64
15:40:53      7      394        2          83        2034     1982        2348        7        10
15:40:54      0      259        1          41        1336     1984         821        2         6
15:40:55      0      357        1         352        4370     1860        8662       90        38
15:40:56      0      324        1          48        1606     1963        1012        3         6
15:40:57     11      404        1          67        2064     1936        1859       23        18
15:40:58      7      361        1          86        1758     1954        1102        5         9
15:40:59      0      313        1          84        2023     1994        1868        3         6
15:41:00      0      280        1          61        1662     1987        1121        3         7
15:41:01      0      278        1          77        1654     1958        1931       13         6
```

对上述参数的解释：

* proc/s: 每秒创建的进程数。此数值是通过fork数来统计的。
* cswch/s: 每秒上下文切换数。
* runqlen：各cpu的运行队列总长度。
* irqtime：CPU响应irq中断所占用的时间。注意这是所有CPU时间的叠加，平均到每个CPU应该除以CPU个数。
* softirq: CPU执行**softirq**所占用的时间，是所有CPU的叠加。softirq：irq中断的下半部，优先级比irq低，可被irq抢占。
* idle: CPU处于空闲状态的时间，所有CPU的叠加。
* kthread: CPU执行**内核线程**所占用的时间，所有CPU的叠加。不包括IDLE-0进程，因为此进程只执行空闲指令使CPU闲置。
* sysc: CPU执行**用户程序系统调用**(syscall)所占用的时间，所有CPU的叠加。
* utime：CPU执行**普通用户进程**时，花在用户态的时间，是所有CPU的叠加。

实现的方式分为3类：

第一类：使用kprobe捕获内核函数的参数，从参数中提取有效信息。如runqlen就是从update_rq_clock的rq参数中提取队列长度信息的。

第二类：使用tracepoint捕获特定状态的开始和结束，计算持续时间。如idle就是利用CPU进出空闲状态的tracepoint来实现功能的。

第三类：获取内核全局变量，直接从内核全局变量读取信息。如proc/s就是通过直接读取total_forks内核全局变量来计算每秒产生进程数的。由于bpf_kallsyms_lookup_name这个helper function不能使用，因此内核符号地址是预先在用户空间从/proc/kallsyms中读取然后传递到bpf程序中的。

由于实际场景的复杂性，因此有些参数实际上是综合使用多种方法实现的。

#### 2.4 调度监测程序(wakeup.py)
思路：研究通用调度器调度过程，得到调度转换时机的发生点，包括进程上下文切换、睡眠和唤醒、等待与等待结束和进程退出。在此过程中，关注CPU、进程PID、调用栈等信息的记录。最后可用以下几种方法展示调度过程：

* 单纯的进程调度事件记录
* 单个进程的调度特征（数值）
* 单个进程的生命周期图示
* 在具体某个CPU核上进程的切换状况

使用方法：
```sh
sudo python3 wakeup.py -h # 显示帮助信息
sudo python3 -t time -p 1234 # 显示1234进程的调度特征，其数据包括运行时间占比、睡眠时间占比、等待时间占比、单次睡眠时间、单个时间片长度、每周期时间片长度等
sudo python3 -t event -o event.txt # 记录进程切换的全量信息，并写入到文件event.txt中
sudo python3 -t lifeline -p 1234 -o event.txt # 记录1234进程的生命周期事件
```

#### 2.5 实用工具

tools/TracepointHelp.sh：用于查看tracepoint列表和特定tracepoint接收参数类型等。其优点是简化了tracepoint的查询过程。

目前支持的功能如下：

1. 打印tracepoint列表：

   ```shell
   ./TracepointHelp.sh -l
   ```

2. 打印特定tracepoint的参数：

   以sched:sched_switch为例，-d后第一个参数是tracepoint所在的类别名，第二个参数是tracepoint的名称。

   ```shell
   ./TracepointHelp.sh -d sched sched_switch
   ```

   输出结果为tracepoint参数的格式信息。在BPF的tracepoint插桩点上，这些参数会以**结构体**的指针的形式输入进来，所以需要预先定义结构体。

   ```txt
   [sudo] zrp 的密码： 
   name: sched_switch
   ID: 316
   format:
           field:unsigned short common_type;       offset:0;       size:2; signed:0;
           field:unsigned char common_flags;       offset:2;       size:1; signed:0;
           field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
           field:int common_pid;   offset:4;       size:4; signed:1;
   
           field:char prev_comm[16];       offset:8;       size:16;        signed:1;
           field:pid_t prev_pid;   offset:24;      size:4; signed:1;
           field:int prev_prio;    offset:28;      size:4; signed:1;
           field:long prev_state;  offset:32;      size:8; signed:1;
           field:char next_comm[16];       offset:40;      size:16;        signed:1;
           field:pid_t next_pid;   offset:56;      size:4; signed:1;
           field:int next_prio;    offset:60;      size:4; signed:1;
   
   print fmt: "prev_comm=%s prev_pid=%d prev_prio=%d prev_state=%s%s ==> next_comm=%s next_pid=%d next_prio=%d", REC->prev_comm, REC->prev_pid, REC->prev_prio, (REC->prev_state & ((((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) - 1)) ? __print_flags(REC->prev_state & ((((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) - 1), "|", { 0x0001, "S" }, { 0x0002, "D" }, { 0x0004, "T" }, { 0x0008, "t" }, { 0x0010, "X" }, { 0x0020, "Z" }, { 0x0040, "P" }, { 0x0080, "I" }) : "R", REC->prev_state & (((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) ? "+" : "", REC->next_comm, REC->next_pid, REC->next_prio
   ```

注：由于对tracepoint信息的访问需要root权限，所以脚本内含有sudo，在执行脚本时可能需要输入用户密码来验证。这是正常操作。

#### 2.6 BCC_cs_delay

BCC_cs_delay是利用bcc对内核函数schedule()的执行时长进行测试的工具，此工具可以对事件进行汇总后再输出，打印为以2为幂的直方图。

以下是sudo python3 cs_delay.py的运行结果：

```
Tracing for Data's... Ctrl-C to end
^C
     cs delay            : count     distribution
         0 -> 1          : 1829     |*******                                 |
         2 -> 3          : 10189    |****************************************|
         4 -> 7          : 9761     |**************************************  |
         8 -> 15         : 2230     |********                                |
        16 -> 31         : 1694     |******                                  |
        32 -> 63         : 817      |***                                     |
        64 -> 127        : 201      |                                        |
       128 -> 255        : 316      |*                                       |
       256 -> 511        : 182      |                                        |
       512 -> 1023       : 483      |*                                       |
      1024 -> 2047       : 300      |*                                       |
      2048 -> 4095       : 383      |*                                       |
      4096 -> 8191       : 409      |*                                       |
      8192 -> 16383      : 150      |                                        |
     16384 -> 32767      : 82       |                                        |
     32768 -> 65535      : 27       |                                        |
     65536 -> 131071     : 2        |                                        |
```

#### 2.7 libbpf_cs_delay

libbpf_cs_delay是利用libbpf对内核函数schedule()的执行时长进行测试的工具，该工具使用了BPF环形缓冲区（ringbuf），避免了BPF性能缓冲区（perfbuf）导致的内存使用效率低和事件重新排序等问题。

运行结果：

```
t1:1321251540  t2:1321251541  delay:1
t1:1321251540  t2:1321251542  delay:2
t1:1321251543  t2:1321251544  delay:1
t1:1321251543  t2:1321251549  delay:6
t1:1321251550  t2:1321251552  delay:2
t1:1321251558  t2:1321251561  delay:3
t1:1321251577  t2:1321251579  delay:2
t1:1321251594  t2:1321251595  delay:1
t1:1321251594  t2:1321251596  delay:2
t1:1321251611  t2:1321251612  delay:1
```

#### 2.8 BCC_cs_delay 和 libbpf_cs_delay测试结果对比

在相同环境下（Ubuntu 22.04），同一时刻对 BCC_cs_delay 和 libbpf_cs_delay 这两个工具进行测试，对比测试结果：

BCC_cs_delay 运行结果：

```
Tracing for Data's... Ctrl-C to end
^C
     cs delay            : count     distribution
         0 -> 1          : 72223    |****************************************|
         2 -> 3          : 54686    |******************************          |
         4 -> 7          : 60225    |*********************************       |
         8 -> 15         : 65366    |************************************    |
        16 -> 31         : 51031    |****************************            |
        32 -> 63         : 7762     |****                                    |
        64 -> 127        : 224      |                                        |
       128 -> 255        : 21       |                                        |
       256 -> 511        : 17       |                                        |
       512 -> 1023       : 49       |                                        |
      1024 -> 2047       : 6        |                                        |
      2048 -> 4095       : 4        |                                        |
      4096 -> 8191       : 1        |                                        |
      8192 -> 16383      : 0        |                                        |
     16384 -> 32767      : 2        |                                        |
```

由于libbpf里没有把结果汇总打印成直方图的函数，所以 libbpf_cs_delay 只能进行如下输出：

```
......
t1:190990630  t2:190990631  delay:1
t1:190990630  t2:190990646  delay:16
t1:190990648  t2:190990649  delay:1
t1:190990648  t2:190990658  delay:10
t1:190990661  t2:190990667  delay:6
t1:190990678  t2:190990679  delay:1
t1:190990694  t2:190990694  delay:0
t1:190990697  t2:190990699  delay:2
t1:190990709  t2:190990710  delay:1
t1:190990709  t2:190990716  delay:7
t1:190990721  t2:190990724  delay:3
t1:190990727  t2:190990745  delay:18
t1:190990754  t2:190990755  delay:1
t1:190990754  t2:190990761  delay:7
t1:190990762  t2:190990770  delay:8
t1:190990762  t2:190990776  delay:14
t1:190990776  t2:190990778  delay:2
t1:190990788  t2:190990795  delay:7
t1:190990788  t2:190990822  delay:34
t1:190990833  t2:190990835  delay:2
t1:190990833  t2:190990842  delay:9
t1:190990843  t2:190990850  delay:7
t1:190990860  t2:190990866  delay:6
t1:190990860  t2:190990872  delay:12
t1:190990878  t2:190990886  delay:8
t1:190990904  t2:190990908  delay:4
t1:190990904  t2:190990912  delay:8
......
```

虽然 libbpf_cs_delay 的运行结果无法在这里显示完全，但是它的输出结果 delay 在虚拟机上据统计也是基本上位于 0 - 31 微秒之间，因此可以得出结论：通过BCC和libbpf写出的测试上下文切换的程序在运行结果上不存在差异。

### 3. eBPF_proc_image

eBPF_proc_image是基于eBPF的Linux系统性能监测工具-进程画像，通过该工具可以清晰展示出一个Linux进程生命周期的如下信息：

- 一个进程从创建到终止的完整生命周期
- 进程/线程持有锁的区间画像
- 进程/线程上下文切换原因的标注
- 线程之间依赖关系（线程）
- 进程关联调用栈信息标注

该工具的参数信息：

| 参数                 | 描述                                              |
| -------------------- | ------------------------------------------------- |
| -p, --pid=PID        | 指定跟踪进程的pid，默认为0号进程                  |
| -t, --time=TIME-SEC  | 设置程序的最大运行时间（0表示无限），默认一直运行 |
| -C, --cpuid=CPUID    | 为每CPU进程设置，其他进程不需要设置该参数         |
| -c, --cputime        | 统计进程上下CPU时间信息                           |
| -e, --execve         | 对进程execve关键时间点进行画像                    |
| -E, --exit           | 对进程exit关键时间点进行画像                      |
| -q, --quote          | 在参数周围添加引号(")                             |
| -K, --keytime        | 对进程的关键时间点进行画像，即execve和exit        |
| -m, --user-mutex     | 对进程的用户态互斥锁进行画像                      |
| -M, --kernel-mutex   | 对进程的内核态互斥锁进行画像                      |
| -r, --user-rwlock-rd | 对进程用户态读模式下的读写锁进行画像              |
| -w, --user-rwlock-wr | 对进程用户态写模式下的读写锁进行画像              |
| -L, --lock           | 对进程的各种锁进行画像                            |
| -f, --fork           | 对fork出来的子进程进行画像                        |
| -F, --vfork          | 对vfork出来的子进程进行画像                       |
| -T, --newthread      | 对pthread_create出来的新线程进行画像              |
| -S, --child          | 对新创建进程和线程进行画像                        |
| -A, --all            | 开启所有的功能                                    |
| -h, --help           | 显示帮助信息                                      |

### 4. cpu_watcher
`cpu_watcher`是一个用于监视系统 CPU 使用情况的工具，它可以帮助用户了解系统在不同负载下的性能表现，并提供详细的统计数据。该工具分为以下几个部分，通过不同的参数控制相关的`ebpf`捕获程序是否加载到内核中：

|        参数        |                    描述                    |
| :----------------: | :----------------------------------------: |
|      -s ：SAR      |     实时采集SAR的各项指标,每秒输出一次     |
|    -p：preempt     |   实时采集当前系统的每次抢占调度详细信息   |
| -d：schedule_delay |         实时采集当前系统的调度时延         |
| -S：syscall_delay  |          实时采集当前系统调用时间          |
|    -m：mq_delay    |        实时采集当前消息队列通信时延        |
|    -c：cs_delay    | 实时对内核函数schedule()的执行时长进行测试 |

### 5. 调研及实现过程的文档

位于docs目录下，由于编码兼容性原因，文件名为英文，但文件内容是中文。

### 5. 联系方式
如对此项目有所建议，或想要参与到此项目的开发当中，欢迎联系邮箱2110459069@qq.com！希望与更多志同道合的人一道探究CPU子系统的指标检测相关问题！
