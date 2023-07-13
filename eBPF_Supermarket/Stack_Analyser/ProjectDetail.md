2023.6.25
- 首先根据进程指标（在线时间）找出异常进程，找到异常进程后拉起栈计数程序跟踪分析异常进程
- 直接使用栈计数程序跟踪分析所有进程的栈，找出数量异常的栈及相关的进程
- 应用在调试上一般直接跟踪相关进程
- 如果应用在系统异常检测上，应该每个进程分别检测
- 利用时序异常检测检测栈变化的异常，也分以上途径

2023.7.8
- 不同进程优先级不同，分得的时间片大小不同，定频采样所有进程的调用栈混在一起没有可比性
- 根据进程指标找出异常进程实际上也是混在一起比较，没有考虑优先级、控制组对资源的特定分配
- 应考虑每个进程分别检测
- 赵晨雨师兄建议将内核栈和用户栈关联

2023.7.9
- 在跟踪所有进程时每个进程只能获取一个调用栈（暂时无法解释），所以跟踪所有进程时分别分析每个进程的主要调用栈的这种方式不可行
- 用来统计所有进程中特殊频次资源消耗的进程栈（目前实现）
- 在运行时设定要跟踪的特定的进程或者运行的命令（计划）
- 分析特定进程的调用栈时序变化

2023.7.10
- 想要跟踪的子进程或者线程可能在跟踪主进程时还未来得及创建，因此无法获取它们的pid
- attach_perf_event可以跟踪设定的pid的子进程
- 优于火焰图的地方，可以看出栈所属的进程
- on-cpu使用计数器而不是时间戳可以提高性能，减少记录次数

2023.7.11

- perf可以在无关栈顶函数的情况下记录栈
- 但off-cpu没办法计数，必须使用时间戳
- 如果要做hot-cold图的话on-cpu也必须以时间戳为单位
- 使用`sudo perf record -a -g -F 997 sleep 60`、`perf script > perf_stack.log`命令记录的stack信息如下：
    ```log
    swapper     0 [003] 604164.215324:    1003009 cpu-clock:pppH: 
        ffffffff81f4108b native_safe_halt+0xb ([kernel.kallsyms])
        ffffffff81f4187b acpi_idle_enter+0xbb ([kernel.kallsyms])
        ffffffff81bb5697 cpuidle_enter_state+0x97 ([kernel.kallsyms])
        ffffffff81bb5cae cpuidle_enter+0x2e ([kernel.kallsyms])
        ffffffff81130493 call_cpuidle+0x23 ([kernel.kallsyms])
        ffffffff8113485d cpuidle_idle_call+0x11d ([kernel.kallsyms])
        ffffffff81134952 do_idle+0x82 ([kernel.kallsyms])
        ffffffff81134bbd cpu_startup_entry+0x1d ([kernel.kallsyms])
        ffffffff810880f2 start_secondary+0x122 ([kernel.kallsyms])
        ffffffff8100015a secondary_startup_64_no_verify+0xe5 ([kernel.kallsyms])
    ```
    头部的条目分别为：comm、tid、time、ip、sym，时间的格式是`s.ns`

