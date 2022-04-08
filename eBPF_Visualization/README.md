# eBPF_Visualization

`eBPF_Visualization`提供一个易用的轻量级的 eBPF 管理系统，目前包括 eBPF 插件、数据管理：

1. 管理 eBPF 组件；

2. 快速便捷地实时展示 Linux 系统性能数据；

3. 可视化展示**应用/进程**从用户态到内核态执行链路；

项目采用前后端分离开发方式，整体由 Web 应用和服务端应用组成，主要功能为eBPF插件数据可视化和内核场景化分析（TODO：场景化分析重新起名字）可视化。

- eBPF_webAdmin：web端功能，包括前后端部分
- eBPF_observability：eBPF可视化组件部分，可脱离webAdmin单独执行
- eBPF_scenario_analysis：eBPF场景化分析组件部分

目前项目正在重构中，欢迎大家参与到方案重构[thought log](./thought_log.md)中^ ^

TODO：将eBPF_observability和eBPF_scenario_analysis部分的README转移到这里来，避免README太多。



#### eBPF插件数据可视化

目标是快速实现eBPF数据的可视化观测，无需添加API，无需部署冗余组件，只需要按照类似BCC工具的输出格式输出即可。

| 类型 | 介绍（TODO：这里可以列出我们现在知道的开发库的github地址，还有很多） |
| ---- | ------------------------------------------------------------ |
| BCC  | https://github.com/iovisor/bcc                               |
| C    | https://github.com/libbpf/libbpf-bootstrap                   |
| GO   | https://github.com/cilium/ebpf                               |
| RUST | https://github.com/libbpf/libbpf-bootstrap                   |

详细介绍参照[README](./eBPF_observability/README.md)



#### eBPF内核场景化分析说明

旨在利用 eBPF 实现 应用/内核事件 的场景化分析，即实现某一 应用/进程 从用户态到内核态执行链路的关键事件分析和可视化。目的如下：

1. 探索 eBPF 能力
2. 为初学者、内核爱好者学习Linux内核提供一种新的可视化方式；
3. 熟悉应用/内核事件执行流程，为使用 eBPF 技术积累知识储备；
4. 体验同一内核事件的不同执行链路，例如不同用户态操作会使用相同的内核事件，但内核事件的执行方式不同；
5. 解决生产问题时，如已定位到某个内核事件，可快速使用仓库中的eBPF代码脚手架；

场景化分析目录如下：

| 项目名称   | 场景介绍                 | 技术栈      | 维护者 |
| ---------- | ------------------------ | ----------- | ------ |
| write      | 将10个字符写入一个空文件 | cilium/ebpf | 孙张品 |
| tr_package | 本地一个数据包的收发流程 | cilium/ebpf | 张翔哲 |

详细介绍参照[README](./eBPF_scenario_analysis/README.md)
