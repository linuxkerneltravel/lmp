## 1. 概述

题目编号：proj154-linux-realtime-probe-tool

本次的项目名称是Linux 内核实时性瓶颈分析工具，由于在工业控制、机器人控制领域中越来越多使用Linux操作系统，但Linux系统在实时性方面天然不具备优势。为了改善Linux实时性，参考eBPF或perf等相关技术原理，研发出一个探针型的工具用于分析造成中断较高的原因，便于内核程序员对症下药。 通过解决有限高延迟路径，从而达到让Linux在多种高负载场景下仍然能够长期保持可接受范围内的延迟。

## 2. 项目成员

**指导老师**：郭皓

**项目成员**：

| 姓名   | 年级 | 专业     |
| ------ | ---- | -------- |
| 张玉哲 | 研二 | 软件工程 |
| 杨骏青 | 研二 | 电子信息 |
| 石泉   | 研一 | 电子信息 |

## 3. 项目架构

目前项目的整体架构图如下所示：

![](https://blog-picture-bed1.oss-cn-hangzhou.aliyuncs.com/image-20220815220855270.png)

## 4. 仓库目录结构

```sh
project788067-126085/
./
├── docs 文档
│   ├── design_docs
│   ├── irq
│   └── env.md
├── include 头文件
│   ├── data.h
│   ├── kfifo.h
│   ├── kprobe.h
│   ├── kthread.h
│   ├── lib.h
│   ├── objpool.h
│   ├── percpu.h
│   ├── proc.h
│   ├── workqueue.h
│   └── xarray.h
├── src	子模块实现
│   ├── data.c
│   ├── kfifo.c
│   ├── kprobe.c
│   ├── kthread.c
│   ├── objpool.c
│   ├── percpu.c
│   ├── proc.c
│   ├── workqueue.c
│   └── xarray.c
├── main.c
├── Makefile
└── README.md
```



## 5. 项目开发进展

| 题目编号                             | 基本完成情况 | 说明                           |
| ------------------------------------ | ------------ | ------------------------------ |
| 第一题：内核模块基础框架实现         | 已实现100%   | 已全部完成                     |
| 第二题：探针工具实际内容实现         | 已实现100%   | 已全部完成                     |
| 第三题：工具稳定性验证和实际效果测试 | 已实现100%   | 已全部完成并在树莓派上成功测试 |

**第一题：内核模块基础框架实现 (已实现100%)**

- [x] shell脚本能够使用自研内核模块的procfs机制与自研内核进行字符串读写
- [x] 自研内核模块内部需要对用户态输入的数据进行分析，并使用链表对数据进行格式化存储
- [x] 自研内核模块内部使用cache机制对格式化存储数据进行存储
- [x] 该工具需要支持开机自启动，读取指定配置文件下发到自研内核模块中

**第二题：探针工具实际内容实现 (已实现100%)**

以题目一为基础，工具需要追加下列功能：

- [x] 自研内核模块增加硬件中断号参数、阈值参数、模块开关，可通过shell工具进行配置和修改
- [x] 自研模块能够根据shell配置的硬件中断号对指定中断或全部中断的关闭中断时长进行检测，精度需要达到纳秒级别
- [x] 自研内核模块能够根据shell配置的阈值参数进行数据过滤，只有关闭时长大于该阈值时才会触发数据抓取操作，抓取内容包括使用该中断的进程相关信息，如调用栈、持有锁、文件、socket等敏感信息
- [x] 抓取后的数据需要使用cache机制存储到内核链表中。shell工具可以通过procfs读取所有抓取到的数据，也可以清空所有抓取到的数据。

**第三题：工具稳定性验证和实际效果测试 (已实现100%)**

以题目二为基础，工具需要追加下列功能：

- [x] 能够在内核态正常长时间运行，不会造成内存泄漏和系统卡顿
- [x] 需要在高负载场景进行工具的功能性和稳定性测试，包括CPU型高负载、内存型高负载、IO型高负载、中断型高负载、综合型高负载


## 6. 项目整体文档

关于项目的整体文档可以通过下面链接查看：

## 结项文档

- [结项文档 - PDF 版本 ](https://gitlab.eduxiji.net/vegeta/project788067-126085/-/blob/master/docs/design_docs/%E7%BB%93%E9%A1%B9%E6%96%87%E6%A1%A3.pdf)

- [结项文档 - Markdown 版本 (推荐) ](https://gitlab.eduxiji.net/vegeta/project788067-126085/-/blob/master/docs/design_docs/%E7%BB%93%E9%A1%B9%E6%96%87%E6%A1%A3.md)

- [结项文档- HTML 版本 ](https://gitlab.eduxiji.net/vegeta/project788067-126085/-/blob/master/docs/design_docs/%E7%BB%93%E9%A1%B9%E6%96%87%E6%A1%A3.html)

## 初赛文档

- [初赛文档 - PDF 版本 ](https://gitlab.eduxiji.net/vegeta/project788067-126085/-/blob/master/docs/design_docs/%E5%88%9D%E8%B5%9B%E6%96%87%E6%A1%A3.pdf)

- [初赛文档 - Markdown 版本 (推荐) ](https://gitlab.eduxiji.net/vegeta/project788067-126085/-/blob/master/docs/design_docs/%E5%88%9D%E8%B5%9B%E6%96%87%E6%A1%A3.md)

- [初赛文档 - HTML 版本 ](https://gitlab.eduxiji.net/vegeta/project788067-126085/-/blob/master/docs/design_docs/%E5%88%9D%E8%B5%9B%E6%96%87%E6%A1%A3.html)


