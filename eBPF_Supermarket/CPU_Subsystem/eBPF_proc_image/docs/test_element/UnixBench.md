# UnixBench

## 一、README

UnixBench 的目的是提供类 Unix 系统性能的基本指标，多个测试用于测试系统性能的各个方面。然后将这些测试结果与从基线系统进行评分以生成指数值，该指数值通常比原始分数更容易处理。 然后，将整组索引值组合在一起，形成系统的整体索引。

UnixBench由许多针对特定领域的单独测试组成。以下是每个测试功能的摘要：

- Dhrystone：这个基准用于测量和比较计算机的性能。测试的重点是字符串处理，因为没有浮点操作。它在很大程度上受到硬件和软件设计、编译器和链接器选项、代码优化、缓存、等待状态和整数数据类型的影响。
- Whetstone：这个测试测量浮点运算的速度和效率。该测试包含几个模块，旨在表示在科学应用中通常执行的混合操作。使用了各种C函数，包括，，，，和，以及整数和浮点数学操作、数组访问、条件分支和过程调用。这个测试测量整数和浮点算术。`sin` `cos` `sqrt` `exp` `log`
- **`execl` Throughput**：该测试测量每秒可以执行的调用数。是exec函数族的一部分，该函数族用新进程映像替换当前进程映像。它和许多其他类似的命令都是该函数的前端。`execl` `execl` `execve()`
- **File Copy**：它测量使用不同缓冲区大小的数据从一个文件传输到另一个文件的速率。文件读、写和复制测试捕获在指定时间内(默认为10秒)可以写、读和复制的字符数。
- **Pipe Throughput**：管道是进程之间最简单的通信形式。管道吞吐量是一个进程每秒可以向管道写入512字节并读取它们的次数。管道吞吐量测试在实际编程中没有对应的对象。
- Pipe-based Context Switching：该测试测量两个进程可以通过管道交换递增整数的次数。基于管道的上下文切换测试更像是一个真实的应用程序。测试程序生成一个子进程，与它进行双向管道对话。
- **Process Creation**：该测试测量进程可以fork和收获立即退出的子进程的次数。进程创建指的是为新进程实际创建进程控制块和内存分配，因此这直接适用于内存带宽。通常，该基准测试将用于比较操作系统进程创建调用的各种实现。
- Shell Scripts：shell脚本测试测量进程每分钟可以启动和获取shell脚本的一组、两组、四组和八组并发副本的次数，其中shell脚本对数据文件应用一系列转换。
- System Call Overhead：这估计了进入和离开操作系统内核的成本，即执行系统调用的开销。它由一个简单的程序组成，反复调用(返回调用进程的进程id)系统调用。执行这些调用的时间用于估计进入和退出内核的成本。`getpid`
- Graphical Tests：提供二维和三维图形测试;目前，特别是3D套件是非常有限的，由程序组成。这些测试旨在对系统的2D和3D图形性能提供一个非常粗略的概念。当然，请记住，报告的性能不仅取决于硬件，还取决于您的系统是否有合适的驱动程序。`ubgears`

## 二、USAGE

### (一) Running the Tests

所有的测试都使用顶层目录中的“Run”脚本执行。

执行“Run”来运行系统测试;“Run graphics”运行图形测试;"Run gindex"运行两者。

生成结果的最简单方法是使用以下命令:

```
./Run
```

这将运行一个标准的“索引”测试(参见下面的“字节索引”)，并将报告保存在“结果”目录中，文件名为hostname-2007-09-23-01，还保存了HTML版本。

如果您希望同时生成基本系统索引和图形索引，则执行以下操作:

```
./Run gindex
```

如果您的系统有多个CPU，测试将运行两次——一次运行每个测试的一个副本，一次运行N个副本，其中N是CPU的数量。但是，某些类别的测试(目前是图形测试)只能使用单个副本运行。

由于测试是基于恒定的时间(可变的工作)，一个“系统”运行通常需要29分钟;“图形”部分大约需要18分钟。在双核机器上运行“gindex”将执行两次“系统”(单处理和双处理)和一次“图形”运行，总共运行大约一个半小时。

### (二) Detailed Usage

Run脚本具有许多选项，您可以使用这些选项来定制测试，并且您可以指定要运行的测试的名称。完整用法是:

```
Run [ -q | -v ] [-i <n> ] [-c <n> [-c <n> ...]] [test ...]
选项标志是:
  -q            在安静模式下运行。
  -v            以详细模式运行。
  -i <count>    为每个测试运行<count>迭代——较慢的测试使用<count> / 3，
				但至少1。默认为10(慢速测试为3)。
  -c <n>        并行运行每个测试的<n>个副本。
```

-c选项可以多次给定;例如:

```
./Run -c 1 -c 4
```

将运行单流通行证，然后是4流通行证。请注意，有些测试(目前是图形测试)只能在单流通过中运行。

其余的非标志参数作为要运行的测试的名称。默认是运行“index”。请参阅下面的“测试”。

在运行测试时，我不建议切换到单用户模式(“init 1”)。这似乎以我不理解的方式改变了结果，这是不现实的(当然，除非您的系统实际上在这种模式下运行)。但是，如果使用窗口系统，您可能希望切换到最小的窗口设置(例如，登录到“twm”会话)，因此，随机搅动的背景过程不会使结果过于随机。对于图像测试来说尤其如此。

输出可以通过设置以下环境变量来指定:

* "UB_RESULTDIR": 结果文件输出目录的绝对路径。
* "UB_TMPDIR": IO测试临时文件的绝对路径。
* “UB_OUTPUT_FILE_NAME”: 输出文件名。如果存在，它将被覆盖。
* "UB_OUTPUT_CSV": 如果设置为"true"，输出结果(仅限分数)为 .csv.

### (三) Tests

现有的测试分为几类;在生成索引分数时(参见下面的“字节指数”)，每个类别的结果是单独产生的。这些类别是:

```
system          原始的Unix系统测试(并非所有测试都在索引中)
2d              2D图形测试(并非所有测试都在索引中)
3d              3D图形测试
misc            各种非索引测试
```

以下单独的测试是可用的:

```
  system:
    dhry2reg         Dhrystone 2使用寄存器变量
    whetstone-double Double-Precision Whetstone
    syscall          系统调用开销
    pipe             管吞吐量
    context1         基于管道的上下文切换
    spawn            进程的创建
    execl            Execl吞吐量
    fstime-w         File Write 1024 bufsize 2000 maxblocks
    fstime-r         File Read 1024 bufsize 2000 maxblocks
    fstime           File Copy 1024 bufsize 2000 maxblocks
    fsbuffer-w       File Write 256 bufsize 500 maxblocks
    fsbuffer-r       File Read 256 bufsize 500 maxblocks
    fsbuffer         File Copy 256 bufsize 500 maxblocks
    fsdisk-w         File Write 4096 bufsize 8000 maxblocks
    fsdisk-r         File Read 4096 bufsize 8000 maxblocks
    fsdisk           File Copy 4096 bufsize 8000 maxblocks
    shell1           Shell Scripts (1 concurrent) (runs "looper 60 multi.sh 1")
    shell8           Shell Scripts (8 concurrent) (runs "looper 60 multi.sh 8")
    shell16          Shell Scripts (16 concurrent)(runs "looper 60 multi.sh 16")
                       环境变量MULTI_SH_WORK_FACTOR(默认为1)可以设置为测试输入数据的大小乘以						   (~8k)。
                       注意:修改MULTI_SH_WORK_FACTOR会修改测试。但是，修改用户/内核工作负载平衡对						   于与使用相同MULTI_SH_WORK_FACTOR运行基准测试的其他系统进行比较可能是有用的。
  2d:
    2d-rects         2D graphics: rectangles
    2d-lines         2D graphics: lines
    2d-circle        2D graphics: circles
    2d-ellipse       2D graphics: ellipses
    2d-shapes        2D graphics: polygons
    2d-aashapes      2D graphics: aa polygons
    2d-polys         2D graphics: complex polygons
    2d-text          2D graphics: text
    2d-blit          2D graphics: images and blits
    2d-window        2D graphics: windows

  3d:
    ubgears          3D graphics: gears

  misc:
    C                C编译器吞吐量("loop 60 $cCompiler cctest.c")
    arithoh          Arithoh (huh?)
    short            Arithmetic Test (short) (this is arith.c configured for
                     "short" variables; ditto for the ones below)
    int              Arithmetic Test (int)
    long             Arithmetic Test (long)
    float            Arithmetic Test (float)
    double           Arithmetic Test (double)
    dc               Dc: sqrt(2)到小数点后99位 (runs"looper 30 dc < dc.dat", 
    				 using your system's copy of "dc")
    hanoi            递归测试 -- Tower of Hanoi
    grep             Grep在大文件中获取字符串，使用系统的" Grep "副本
    sysexec          Exercise fork() and exec().
```

以下伪测试名称是其他测试组合的别名:

```
    arithmetic       Runs arithoh, short, int, long, float, double,
                     and whetstone-double
    dhry             Alias for dhry2reg
    dhrystone        Alias for dhry2reg
    whets            Alias for whetstone-double
    whetstone        Alias for whetstone-double
    load             Runs shell1, shell8, and shell16
    misc             Runs C, dc, and hanoi
    speed            Runs the arithmetic and system groups
    oldsystem        Runs execl, fstime, fsbuffer, fsdisk, pipe, context1,
                     spawn, and syscall
    system           Runs oldsystem plus shell1, shell8, and shell16
    fs               Runs fstime-w, fstime-r, fstime, fsbuffer-w,
                     fsbuffer-r, fsbuffer, fsdisk-w, fsdisk-r, and fsdisk
    shell            Runs shell1, shell8, and shell16

    index            运行构成官方索引的测试:
                     the oldsystem group, plus dhry2reg, whetstone-double,
                     shell1, and shell8
                     See "The BYTE Index" below for more information.
    graphics         Runs the tests which constitute the graphics index:
                     2d-rects, 2d-ellipse, 2d-aashapes, 2d-text, 2d-blit,
                     2d-window, and ubgears
    gindex           Runs the index and graphics groups, to generate both
                     sets of index results

    all              Runs all tests
```

### (四) The BYTE Index

这个测试的目的是提供一个类unix系统性能的基本指标；因此，使用多个测试来测试系统性能的各个方面。然后将这些测试结果与基线系统的分数进行比较，以产生指标值，该指标值通常比原始数据更容易处理。然后将整个索引值集合组合起来，形成系统的总体索引。

**自1995年以来，基准系统一直是“George”**，SPARCstation 20-61，具有128 MB RAM, SPARC存储阵列和Solaris 2.3，其评级设置为10.0。(所以一个520分的系统比这台机器快52倍。)由于数字只是在相对意义上有用，因此没有特别的理由更新基本系统，因此为了一致性起见，最好不要使用它。**George的分数在“pgms/index.base”文件中;该文件用于计算任何特定运行的索引分数。**

多年来，对指数中的测试集进行了各种更改。虽然希望有一个一致的基线，但已确定各种测试具有误导性，并已取消;而且还增加了一些替代方案。这些更改在README中有详细说明，在查看旧的分数时应该牢记这些更改。

由于各种原因，基准套件中包含了一些不属于索引的测试;当然，这些测试可以手动运行。请参阅上面的“Tests”。

### (五) Graphics Tests

从5.1版本开始，UnixBench现在包含了一些图形基准测试。这些是为了给出一个系统的一般图形性能的大致概念。

图形测试分为“2d”和“3d”两类，因此这些测试的指数分数与基本系统指数是分开的。这似乎是一个合理的划分，因为系统的图形性能在很大程度上取决于图形适配器。

目前的测试包括一些2D“x11perf”测试和“ubgears”测试。

* 2D测试是x11perf测试的一个选择，使用主机系统的x11perf命令(必须安装该命令并在搜索路径中)。为了在合理的时间内完成测试运行，只使用少量的x11perf测试;如果您想对X服务器或图形芯片进行详细的诊断，那么直接使用x11perf。
  
* 3D测试是“ubgears”，是我们熟悉的“glxgears”的改良版。这个版本运行5秒来“预热”，然后执行定时运行并显示平均每秒帧数。

在多cpu系统上，图形测试只能在单处理模式下运行。这是因为同时运行两个测试副本的意义是可疑的;测试窗口往往相互覆盖，这意味着后面的窗口实际上没有做任何工作。

### (六) Multiple CPUs

如果您的系统有多个cpu，默认行为是运行所选测试两次——一次运行每个测试程序的一个副本，一次运行N个副本，其中N是cpu的数量。(你可以用"-c"选项覆盖它;参见上面的“详细用法”。)这是为了让你评估:

 - 运行单个任务时系统的性能
 - 运行多个任务时系统的性能
 - 系统实现并行处理的收益

然而，结果需要小心处理。以下是在双处理器系统上运行两次的结果，一次在单处理模式下，一次在双处理模式下:

```
  Test                    Single     Dual   Gain
  --------------------    ------   ------   ----
  Dhrystone 2              562.5   1110.3    97%
  Double Whetstone         320.0    640.4   100%
  Execl Throughput         450.4    880.3    95%
  File Copy 1024           759.4    595.9   -22%
  File Copy 256            535.8    438.8   -18%
  File Copy 4096          1261.8   1043.4   -17%
  Pipe Throughput          481.0    979.3   104%
  Pipe-based Switching     326.8   1229.0   276%
  Process Creation         917.2   1714.1    87%
  Shell Scripts (1)       1064.9   1566.3    47%
  Shell Scripts (8)       1567.7   1709.9     9%
  System Call Overhead     944.2   1445.5    53%
  --------------------    ------   ------   ----
  Index Score:             678.2   1026.2    51%
```

正如预期的那样，高度依赖cpu的任务——dhrystone、wheetstone、execl、管道吞吐量、进程创建——在并行运行2个副本时显示出接近100%的增益。

基于管道的上下文切换测试通过在两个进程之间来回发送消息来度量上下文切换开销。我不知道为什么它显示出如此巨大的增益与2副本(即。总共4个进程)正在运行，但在我的系统上似乎是一致的。我认为这可能是SMP实施的一个问题。

系统调用开销显示出较小的增益，可能是因为它在单线程内核代码中使用了大量CPU时间。使用8个并发进程的shell脚本测试没有显示出任何增益——因为测试本身并行运行8个脚本，它已经使用了两个cpu，即使基准测试是在单流模式下运行。对每个副本使用一个进程的相同测试显示了实际的增益。

当进行多处理时，文件系统吞吐量测试显示的是损失，而不是增加。没有预期的增益，因为测试可能受到I/O子系统和磁盘驱动器本身的吞吐量的限制;性能的下降可能是由于资源争用的增加，也许是由于磁盘磁头移动的增加。

那么应该使用哪些测试，应该运行多少个副本，以及应该如何解释结果?这取决于你，因为这取决于你要测量的是什么。

**实现：**

多处理模式在测试迭代级别上实现。在测试的每次迭代期间，使用fork()启动N个从属进程。每个从服务器都使用fork()和exec()执行测试程序，读取并存储整个输出，对运行进行计时，并将所有结果打印到管道中。Run脚本依次读取每个从服务器的管道，以获得结果和时间。分数被加起来，时间被平均。

结果是每个测试程序同时运行N个副本。它们应该在同一时间完成，因为它们运行的时间是恒定的。

如果一个测试程序本身启动了K多个进程(与shell8测试一样)，那么结果将是同时运行N * K个进程。这对于测试多cpu性能可能不是很有用。

### (七) The Language Setting

$LANG环境变量决定程序和库例程如何解释文本。这对测试结果有很大的影响。

如果$LANG被设置为POSIX，或者未设置，文本将被视为ASCII;如果设置为en_US。例如，如果使用UTF-8编码，则文本将被视为使用UTF-8编码，这更复杂，因此速度更慢。将其设置为其他语言可能会产生不同的结果。

为了确保测试运行之间的一致性，Run脚本现在(从版本5.1.1开始)将$LANG设置为"en_US.utf8"。

这个设置是用变量“$language”配置的。如果你想要分享你的结果以便在系统之间进行比较，你就不应该改变这一点;但是，您可能希望更改它以查看不同的语言设置如何影响性能。

现在，每个测试报告都包含正在使用的语言设置。报告的语言是在$LANG中设置的，系统不一定支持;但是我们也报告实际使用的字符映射和排序顺序(由“locale”报告)。

### (八) Interpreting the Results

解释这些测试的结果是很棘手的，完全取决于你想要测量什么。

例如，您是否正在尝试测量CPU的速度?或者你的编译器有多好?因为这些测试都是使用主机系统的编译器重新编译的，所以编译器的性能将不可避免地影响测试的性能。这是个问题吗?如果你正在选择一个系统，你可能会关心它的整体速度，这可能取决于它的编译器有多好;所以在测试结果中包含这一点可能是正确的答案。但是您可能希望确保使用正确的编译器来构建测试。

另一方面，由于绝大多数Unix系统是x86 / PC兼容的，运行Linux和GNU C编译器，结果将倾向于更依赖于硬件;但是编译器和操作系统的版本会有很大的不同。(在同一台机器上，我测试了SUSE 10.1和OpenSUSE 10.2的性能提升了50%。)所以你可能想要确保你所有的测试系统都运行相同版本的操作系统;或者至少发布操作系统和计算机版本的结果。不过，您感兴趣的可能是编译器的性能。

C测试非常可疑——它测试的是编译速度。如果你在每个系统上运行完全相同的编译器，没问题;但除此之外，结果可能应该被抛弃。较慢的编译并不能说明系统的速度，因为编译器可能只是花了更多的时间来超级优化代码，这实际上会使它更快。

这在IA-64 (Itanium等)这样的架构上尤其如此，因为编译器会花费大量的精力来调度并行运行的指令，从而显著提高执行速度。

有些测试在主机依赖性方面甚至更加可疑——例如，“dc”测试使用主机版本的dc(一个计算器程序)。可用的版本可以对分数产生巨大的影响，这就是为什么它不在索引组中。请通读发行说明，了解有关这类问题的更多信息。

另一个由来已久的问题是，基准太过琐碎，没有意义。随着编译器变得越来越智能，并执行更广泛的流路径分析，部分基准测试被优化而不存在的危险总是存在的。

总而言之，“index”和“gindex”测试(见上文)的设计目的是给出系统整体性能的合理度量;但是任何测试运行的结果都应该谨慎使用。

## 三、工具源码阅读笔记

### (一) 工具参数

| 参数                     | 含义                                                         |
| ------------------------ | ------------------------------------------------------------ |
| 不以 - 开头              | 将其视为基准测试名称，并根据测试列表 `$testList` 添加相应的基准测试 |
| all                      | 将所有基准测试添加到 `$tests` 中                             |
| 既不是测试名称也不是 all | 抛出错误                                                     |
| -q                       | 将 `$params->{'verbose'}` 设置为 0（安静模式）               |
| -v                       | 将 `$params->{'verbose'}` 设置为 2（详细模式）               |
| -i                       | 将 `$params->{'iterations'}` 设置为下一个单词                |
| -c                       | 用于在基准测试中设置并发度                                   |

### (三) 基准测试的调用路径

```
<Run>
main()->
	runTests()->
		runBenchmark()-$prog-$command-$params->
			runOnePass($params, $verbose, $logFile, $copies)->
				...
```

## 四、测试元素的选取

### 1. System Call Overhead

**System Call Overhead**：这估计了进入和离开操作系统内核的成本，即执行系统调用的开销。它由一个简单的程序组成，反复调用(返回调用进程的进程id)系统调用。执行这些调用的时间用于估计进入和退出内核的成本。`getpid`

测试程序中的相关代码：

```
           // 在循环中调用 getpid 系统调用
           while (1) {
                syscall(SYS_getpid);
                iter++;
           }
```

**测试程序与eBPF程序涉及思路：**

- 测试程序：

  - 改善自己的测试程序，可适当的加入参数控制
  - 加入上述代码逻辑，限制迭代次数，用于验证采集到的系统调用序列的正确性

- eBPF程序：

  - 修改系统调用序列为每满n个就进行输出（n值可参考系统调用的异常检测论文）

  - 系统调用功能类中加入：

    - 平均系统调用运行延迟
    - 最大系统调用运行延迟

  - 修改系统调用类的输出形式为：

    ```
    SYSCALL-------------------------------------------------------------------------
    TIME  PID  1st(num)  2nd(num)  3nd(num)  AVG_DELAY(ns)  MAX_DELAY(ns)  SYSCALLS
    ```