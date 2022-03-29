## LMP 项目目标：

1. 面向 eBPF 初学者，为初学者提供 eBPF 学习资料、程序案例，构建 eBPF 的学习社区，
2. 孵化 eBPF 相关工具、项目

## LMP 子项目：

在 LMP 下面划分了几个子项目，目标是从多方面梳理收集 eBPF 的文档和相关代码，并且基于此能够持续集合社区力量孵化一些适合学习的代码和好玩的工具性项目。

一下是目前 LMP 开设的子项目，如果大家有更好的建议，也希望多提出来，大家一起规划建设。

||子项目|项目介绍|备注|
|-|-|-|-|
|子项目1|eBPF_admin|为 eBPF 程序管理而开发的 web 管理系统，同时负责人对 eBPF 程序采集数据的可视化展示。||
|子项目2|eBPF_observability|积累开发基于 eBPF 的内核可观测性组件||
|子项目3|eBPF_analysis|基于 eBPF 开发的内核分析组件||
|子项目4|eBPF_function|基于 eBPF 的功能性组件，增强内核功能||
|子项目5|eBPF_mini_projects|基于 eBPF 的小工具，小系统或小项目||
|子项目6|eBPF_docs|收集梳理的针对 eBPF 的相关资料文档||


### 子项目1：eBPF_admin
#### web
#### server


### 子项目2：eBPF_observability

该项目的目标是收集梳理基于 eBPF 的可观测性组件，从各种实现方式，各个角度对内核进行可观测。

欢迎大家体验使用这里的组件，更欢迎大家贡献更多的基于 eBPF 的可观测性程序。

|类型|介绍|备注|
|-|-|-|
|BCC|BCC 的 eBPF 可观测性程序||
|C|使用 C 开发的 eBPF 可观测性程序||
|GO|使用 GO 开发的 eBPF 可观测性程序||
|RUST|使用 RUST 开发的 eBPF 可观测性程序||

更多说明请查看 eBPF_observability 项目的 [README](eBPF_observability/README.md)



### 子项目3：eBPF_scenario_analysis

本仓库下项目旨在利用 eBPF 实现 应用/内核事件 的场景化分析，即实现某一 应用/进程 从用户态到内核态执行链路的关键事件分析和可视化。目的如下：

1. 探索 eBPF 能力
2. 为初学者、内核爱好者学习Linux内核提供一种新的可视化方式
3. 熟悉应用/内核事件执行流程，为使用 eBPF 技术积累知识储备
4. 体验同一内核事件的不同执行链路，例如不同用户态操作会使用相同的内核事件，但内核事件的执行方式不同
5. 解决生产问题时，如已定位到某个内核事件，可快速使用仓库中的eBPF代码脚手架

更多说明请查看 eBPF_scenario_analysis 仓库的 [README](eBPF_scenario_analysis/README.md)

### 子项目4：eBPF_function
本仓库下项目旨在利用 eBPF 实现具体 应用/内核态 功能，包括但不限于性能优化、安全、网络、eBPF编排等功能。目的如下：

1. 没有任何限制，充分发挥想象力，在该处展示自己的想法并获得他人的关注，迭代优化 方案；
2. 可探索 eBPF 与其它技术的结合运用能力，例如引入机器学习模型实现预测等功能；

更多说明请查看 eBPF_function 仓库的 [README](eBPF_function/README.md)

### 子项目5：eBPF_mini_projects

本仓库下项目旨在收集各种利用 eBPF 实现的小工具，小项目，功能不限。目的和要求如下：

1. 只要基于 eBPF 的项目都可以。
2. 有相对完整的目标和功能，需要有负责人的维护者。

更多说明请查看 eBPF_mini_projects 仓库的 [README](eBPF_mini_projects/README.md)

### 子项目6：eBPF_docs

本仓库存放关于 eBPF 相关的文档，为大家提供学习帮助，目前文档主要类别如下：

1. LMP 项目的说明文档，包括项目说明、部署、开发文档等；
2. eBPF 相关的外文翻译，收集经典的国外文献，进行翻译，供大家参考；
3. eBPF 的其他类文档。

更多说明请查看 ebpf_docs 仓库的 [README](ebpf_docs/README.md)