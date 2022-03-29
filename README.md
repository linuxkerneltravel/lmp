![](./eBPF_docs/static/imgs/LMP-logo.png)
# Linux Microscope (LMP)

## LMP 项目目标：

1. 面向 eBPF 初学者和爱好者，提供 eBPF 学习资料、程序/项目案例，构建 eBPF 学习社区
2. 成为 eBPF 想象力集散地，我们相信每一位 eBPF 初学者和爱好者都有无限的想象力，一个想法、一段话甚至是一个问题都是你发挥想象力的方式
3. 孵化 eBPF 相关工具、项目

为实现我们的目标，目前 LMP 提供六个子项目，正在建设中，欢迎各位的建议 ^ ^

## LMP 子项目：

||子项目|项目介绍|备注|
|-|-|-|-|
|子项目1|eBPF_Bright_Projects|存放 eBPF 好点子，没有任何限制，可以是一篇文档，一段代码，也可以是一个工具，一个项目||
|子项目2|eBPF_admin|为 eBPF 程序管理而开发的 web 管理系统，同时可快速对 eBPF 采集的数据进行可视化展示。|方案重构阶段|
|子项目3|eBPF_observability|基于 eBPF 的应用/内核可观测性组件，可在 eBPF_admin 中进行可视化观测||
|子项目4|eBPF_scenario_analysis|基于 eBPF 开发的场景化分析组件，关注具体的执行链路、关键应用/内核事件|正在开发中|
|子项目5|eBPF_function|基于 eBPF 开发的功能性组件，增强内核功能||
|子项目6|eBPF_docs|社区收集、梳理和原创的 eBPF 相关资料和文档||



### 子项目1：eBPF_Bright_Projects

旨在收集各种 eBPF 的好点子，一个想法、一篇文章、一段代码、一个工具、一个项目，都可以是你开始 eBPF 之旅的起点：

1. 没有任何限制；
2. 我们希望你的 pr 有相对完整的结构，如果是代码或项目形式，需要提供 README 以便于他人快速理解你的想法；

更多说明请查看 eBPF_Bright_Projects 仓库的 [README](eBPF_Bright_Projects/README.md)



### 子项目2：eBPF_admin

旨在提供更加易用的 eBPF 组件管理系统，并提供 eBPF组件 工作过程和数据的可视化展示。项目目标如下：
1. 管理 eBPF 组件；
2. 快速便捷地实时展示 Linux 系统性能数据；
3. 可视化展示**应用/进程**从用户态到内核态执行链路；

项目采用前后端分离开发方式，整体由 Web 应用和服务端应用组成。

##### web 端
该项目的目标是收集梳理基于 eBPF 的可观测性组件，从各种实现方式，各个角度对内核进行可观测。

Web 应用目标如下：
1. 用户信息管理；
2. eBPF 组件信息管理；
3. eBPF 数据可视化；
4. eBPF 场景化分析可视化；

##### server 端

服务端应用目标如下：
1. 提供 `RESTful` 风格 `API` 和接口说明文档；
2. 基于 `JWT` 的用户校验；
3. 进行 eBPF 组件信息和用户信息的持久化存储；

更多说明请查看 eBPF_admin 仓库的 [README](eBPF_admin/README.md)



### 子项目3：eBPF_observability

旨在收集梳理基于 eBPF 的应用/内核可观测性组件，可选择任意可行的技术栈。

欢迎大家体验并提出宝贵意见，也欢迎大家贡献更多的基于 eBPF 的可观测性组件，技术栈可参考如下方式：

|类型|介绍|备注|
|-|-|-|
|BCC|使用 BCC python方式开发 eBPF 可观测性组件||
|C libbpf|使用 C libbpf 开发 eBPF 可观测性组件||
|GO|使用 GO 开发的 eBPF 可观测性组件，例如 cilium/ebpf，iovisor/gobpf 等||
|RUST|使用 RUST 开发的 eBPF 可观测性组件||

更多说明请查看 eBPF_Observability 项目的 [README](eBPF_observability/README.md)



### 子项目4：eBPF_scenario_analysis

旨在利用 eBPF 实现 应用/内核事件 的场景化分析，即实现某一 应用/进程 从用户态到内核态执行链路的关键事件分析和可视化：

1. 探索 eBPF 能力；
2. 为初学者、内核爱好者学习Linux内核提供一种新的可视化方式；
3. 熟悉应用/内核事件执行流程，为使用 eBPF 技术积累知识储备；
4. 体验同一内核事件的不同执行链路，例如不同用户态操作会使用相同的内核事件，但内核事件的执行方式不同；
5. 解决生产问题时，如已定位到某个内核事件，可快速使用仓库中的eBPF代码脚手架；

更多说明请查看 eBPF_Scenario_Analysis 仓库的 [README](eBPF_scenario_analysis/README.md)



### 子项目5：eBPF_function
本仓库下项目旨在利用 eBPF 实现具体 应用/内核态 功能，包括但不限于性能优化、安全、网络、eBPF编排等功能。目的如下：

1. 没有任何限制，充分发挥想象力，在该处展示自己的想法并获得他人的关注，迭代优化 方案；
2. 可探索 eBPF 与其它技术的结合运用能力，例如引入机器学习模型实现预测等功能；

更多说明请查看 eBPF_Function 仓库的 [README](eBPF_function/README.md)



### 子项目6：eBPF_docs

本仓库存放 eBPF 和 LMP 相关文档，为大家提供学习指引，规划类别如下：

1. eBPF 入门文档；
2. eBPF 学习清单；
3. eBPF 详细学习资料；
4. eBPF 编程技巧；
5. LMP 下子项目说明、部署、开发文档；

目前文档主要类别如下：

1. LMP 项目的说明文档，包括项目说明、部署、开发文档等；
2. eBPF 相关的外文翻译，收集经典的国外文献，进行翻译，供大家参考；
3. eBPF 的其他类文档；

更多说明请查看 eBPF_Docs 仓库的 [README](eBPF_docs/README.md)