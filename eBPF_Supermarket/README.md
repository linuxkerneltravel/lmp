## eBPF_Supermarket 仓库说明

eBPF工具集散地

1. 工具用途不作强制要求，在该处展示自己的想法并获得他人的关注，迭代优化方案；
2. 我们希望你的 pr 有相对完整的结构，需要提供 README 以便于他人快速理解你的想法；
3. 可探索 eBPF 与其它技术的结合运用能力，例如引入机器学习模型实现预测、异常检测等功能；

## 子项目目录

| 项目名称ZH                                   | EN                                                               | 一句话介绍                                                   | 维护者 |
| -------------------------------------------- |------------------------------------------------------------------| ------------------------------------------------------------ | ------ |
| 基于eBPF的DDoS攻击检测和防御                 | DDoS attack detection and defense based on eBPF                  | 实现固定IP地址的SYN Flood攻击检测和防御                      | 张孝家 |
| NUMA节点的CPU UNCORE共享资源的争用感知与评估 | NUMA_Contention_Awareness                                        | 检测NUMA架构中共享资源的争用情况变化                         | 贺东升 |
| SPV                                          | SPV                                                              | 集中于调度以及dvfs、cpuidle相关数据的收集与分析              | 张玉哲 |
| trace application process                    | trace_application_process                                        | 追踪一个应用程序下所有进程/线程的动态变化                    | 赵晨雨 |
| eBPF数据收集器                               | eBPF_data_collector                                              | eBPF数据收集器                                               | 赵晨雨 |
| 基于eBPF的网络拥塞观测与排查                 | Network congestion observation and troubleshooting based on eBPF | 通过监控内核中的网络延迟抖动、网络拥塞状态机的切换帮忙网络问题排查 | 董旭   |
| eBPF初学者体验环境                           | tryebpf                                                          | 提供bpftrace、BCC等适合初学者上手使用的线上环境              | 白宇宣 |
| Interrupt Exception      | Interrupt_exception                                              | 采集Linux系统异常中断相关信息、包括中断类型号以及函数调用栈等              | 张翔哲 |
| 基于 eBPF 的云原生场景下 Pod 性能监测                           | cilium_ebpf_probe                                                | 针对云原生领域下的Pod提供进程级别的细粒度监测              | 汪雨薇 |
| 基于 eBPF 的云原生场景下 sidecar 性能监测 | sidecar                                                          | 针对云原生场景下 sidecar 的工作原理进行内核层面的观测和优化 | [@ESWZY](https://github.com/ESWZY) |
| 基于 eBPF 的Linux系统性能监测工具-网络子系统 | Linux network subsystem monitoring based on eBPF                 | 基于eBPF机制对Linux系统网络子系统的TCP层进行性能监测 | [@AnneY](https://github.com/AnneYang720) |
| 基于 eBPF 的 XDP 研究与应用 | Research and application of XDP based on eBPF                    | 基于eBPF XDP机制打造一个工具使系统性能得到提升 | [@byxzone](https://github.com/byxzone) |
|  | CPU_Subsystem                                                    |  |  |
|  | eBPF_DDos                                                        |  |  |
|  | eBPF_dns_cache                                                   |  |  |
|  | CPU_Subsystem                                                    |  |  |
|  | Filesystem_Subsystem                                             |  |  |
|  | LSM_BPF                                                          |  |  |
|  | Memory_Subsystem                                                 |  |  |
|  | XDP_Res-Application                                             |  |  |


