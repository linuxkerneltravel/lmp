# 基于 eBPF 的 XDP 研究与应用

- [项目介绍](#项目介绍)
- [针对 eBPF/XDP 的研究](#针对-ebpfxdp-的研究)
  - [XDP 基本工作原理](#xdp-基本工作原理)
  - [XDP 在 virtio-net 网卡驱动上的实现源码分析](#xdp-在-virtio-net-网卡驱动上的实现源码分析)
  - [XDP 与 DPDK/RDMA 的对比分析](#xdp-与-dpdkrdma-的对比分析)
  - [在 eBPF/XDP 程序中计算 checksum](#在-ebpfxdp-程序中计算-checksum)
- [针对 eBPF/XDP 的应用](#针对-ebpfxdp-的应用)
  - [背景知识:iptables/netfilter](#背景知识iptablesnetfilter)
  - [基于 XDP 实现轻量级防火墙](#基于-xdp-实现轻量级防火墙)
  - [基于 XDP 实现快速路由转发](#基于-xdp-实现快速路由转发)

## 项目介绍

eBPF 是在 Linux 内核中运行的抽象虚拟机（VM），可以在内核的沙盒中执行用户定义的程序，以确保最佳性能且无侵入式的方式在内核中编写监控、跟
踪或网络程序。
XDP 提供了一个内核态下高性能的可编程包处理框架，可在最早可以处理包的位置（即网卡驱动收到包的时刻）运行 BPF 程序，其具有非常优秀的数据面处理性能，打通了 Linux 网络处理的高速公路。XDP 暴露了一个可以加载 BPF 程序的网络钩子。在这个钩子中，程序能够对传入的数据包进行任意修改和快速决策，避免了内核内部处理带来的额外开销。

本项目基于 eBPF 和 XDP 进行研究，完成的内容包括：
- 分析 eBPF XDP 实现的基本原理。
- 对比 XDP 和其它方案的优缺点，找出其适合的应用场景。
- 针对该应用场景进行编程设计，并可达到性能提升或安全性提升的效果。

## 针对 eBPF/XDP 的研究

### XDP 基本工作原理

文档:[xdp_basic.md](./docs/xdp/xdp_basic.md)

### XDP 在 virtio-net 网卡驱动上的实现源码分析

文档:[implement_in_virtio.md](./docs/xdp/implement_in_virtio.md)

### XDP 与 DPDK/RDMA 的对比分析

文档:[compare.md](./docs/xdp/compare.md)

### 在 eBPF/XDP 程序中计算 checksum

文档:[checksum_calc.md](./docs/xdp/checksum_calc.md)

## 针对 eBPF/XDP 的应用

### 背景知识:iptables/netfilter

- iptables/netfilter 介绍:[iptables_basic.md](./docs/iptables_netfilter/iptables_basic.md)

- iptables/netfilter 内核实现源码分析:[kernel_implement.md](./docs/iptables_netfilter/kernel_implement.md)


### 基于 XDP 实现轻量级防火墙

根据`rules.txt`中指定的规则(包括:运输层协议/源ip/目的ip/源port/目的port)进行工作.如:

```
ICMP 0          0 0 0  DROP
TCP  3232266753 0 0 80 DROP
```

第一条规则是对所有 ICMP 协议的 packet 执行 drop 操作.

第二条规则是对所有 TCP 协议,且源 ip 地址为`192.168.122.1`目标端口为 80 的 packet 执行drop 操作.

在匹配时使用了一种类O(1)匹配机制,提高了匹配效率,具体实现方法:[match.md](./docs/design/match.md)

运行:

```
sudo python3 ./tools/xdp_filter/filter.py -i INTERFACE -m MODE -t TIME_LIMIT`
```

interface 如`eth0`,mode支持:`0`-generic mode/`1`-native mode,time为运行时间(sec)

### 基于 XDP 实现快速路由转发

使用 Helpers 函数`bpf_fib_lookup` 查找内核路由表,在 XDP 层进行转发.并使用 Map 缓存查找到的路由信息,以便下次直接从缓存中读取数据,加快转发速度.具体实现思路:[fast_forward.md](./docs/design/fast_forward.md)

运行:

```
sudo python3 ./tools/xdp_fast_forward/forward.py -i INTERFACE -m MODE -t TIME_LIMIT
```

参数功能同上

### 整合

使用 XDP 进行路由转发时,是在 iptables/netfilter 之前进行的,所以会导致许多安全策略失效,所以以上二者进行整合,可以实现带有基本防火墙功能的快速路由转发.

整合正在进行中,目录:`./src`