
参考博客：<https://blog.csdn.net/21cnbao/article/details/115912062>
其背后的思想其实就是：与其把数据包复制到用户空间执行用户态程序过滤，不如把过滤程序灌进内核去。

参考视频：[操作系统与Linux内核 & eBPF演示学习 直播回放 - Linux内核之旅](https://www.bilibili.com/video/BV1vL4y1G7R2?spm_id_from=333.999.0.0)
以下为视频摘要：
#### bpf是干什么的？  
ebpf官网-文章《what is ebpf》  
拓展内核的功能，更好地感知内核-实现内核可观测性，内核性能优化，系统安全防护  
内核探针kprobe去分析函数，提取数据到用户态下去处理  

#### 如何学习？  
官网blog  
greg博客  
《bpf之巅》《性能之巅》-较复杂  

#### 如何应用？
例：获取CPU利用率  
win:任务管理器-信息少  
linux:top-有缺陷，通过proc文件系统，依赖时钟中断，有偏差  
bpf:py脚本-更准确更自由，看到更多的信息  
（关于模拟top偏差的原理有点点懵）  

#### 如何写bpf程序？  
- bcc前端，bpftrace，Jbpf  
- 程序主体：C+Python  
- C程序-放入内核执行  
    使用内核函数finish_task_switch读取出程序的pid  
    bpf_get_current_pid_tgid获取转换后的pid  
    放入哈希表BPF_HASH-BPF_HASH使得用户态和内核态进行沟通（如何做到？）  
- 其余程序部分在用户态下执行  
    kprobe表示函数switch_start函数追踪的是内核函数finish_task_switch的信息  
    轮询哈希表将两种pid打印出来  
- 程序执行流程  
    py脚本通过bcc会生成ebpf字节码  
    通过bpf系统调用传入到内核之中  
    进入内核首先通过验证器-即检查安全性  
    Jit将字节码转换成指令集  
    内核即可高效地执行指令集  
    bpf程序执行得到的数据通过ebpf maps映射到用户态下-如BPF_HASH  
  
可以通过ebpf来协助内核学习，更加直观  
