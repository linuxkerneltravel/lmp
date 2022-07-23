# 基于eBPF的Linux系统性能监测工具-网络子系统

## 0. 介绍

本目录基于eBPF机制对Linux系统网络子系统关键性能参数进行监测。

bpftrace_application 是一些 Bpftrace 构建的例程，需要预装 bpftrace，其特点是代码简单，能很快上手，缺点是不能支撑高复杂性的 eBPF 应用。

其余以 go_ 开头的各个文件夹是用 go语言 + eBPF 构建的eBPF例程，使用了开源的cilium/eBPF库，可以支撑高复杂性、模块化的 eBPF 应用。

## 1. 准备工作

开发环境
* 系统：Debian GNU/Linux 11
* 内核：5.13.0-30-generic
* Python 3.9.2
* bcc

## 2. 应用
### 2.1 nic_throughput

每秒输出指定网卡发送与接收的字节数、包数与包平均大小。

参数如下：
```
-n，--name
    [必选] 网卡名称
-i, --interval
    [可选] 输出时间间隔，默认为1

```

运行示例 `sudo python nic_throughput.py -n lo`

输出样例
``` shell
Sat Jul 23 21:50:51 2022
TX
 QueueID    avg_size   BPS        PPS
 0          64.0       384.0      6.0
 Total      64.0       384.0      6.0

RX
 QueueID    avg_size   BPS        PPS
 0          50.0       300.0      6.0
 Total      50.0       300.0      6.0
------------------------------------------------------------
```

### 2.2 tcpconnection

实时输出成功建立的tcp连接，包括时间、进程号、进程名称、IPv4/IPv6、目标ip、目标端口、源ip、源端口、方向（connect/accept）。

参数如下：
```
-p，--pid
    [可选] 指定进程
-P, --port
    [可选] 指定源端口
-4, --ipv4
    [可选] 仅输出IPv4连接
-6, --ipv6
    [可选] 仅输出IPv6连接
-r, --direction
    [可选] 仅输出方向为connect或accept的连接

```

运行示例 
``` shell
sudo python tcpconnection.py -P 80,81  # only trace port 80 and 81
sudo python tcpconnection.py -p 181    # only trace PID 181
sudo python tcpconnection.py -4        # only trace IPv4 family
sudo python tcpconnection.py -6        # only trace IPv6 family
sudo python tcpconnection.py -r accept # only trace accept tcp connections
```

输出样例
``` shell
TIME      PID     COMM         IP DADDR            DPORT SADDR            SPORT  DIRECTION
21:59:03  753526  java         4  127.0.0.1        2181  127.0.0.1        36702    connect
21:59:03  3048248 java         4  127.0.0.1        2181  127.0.0.1        36698    connect
21:59:03  2475785 java         4  127.0.0.1        2181  127.0.0.1        36700    connect
21:59:03  2475720 java         4  172.17.0.2       2181  172.17.0.5       45194    connect
```

## 3. 文档
docs目录下主要放置了开发过程中，形成的文档

| doc | content |
| ------ | ------ |
| README | 网络子系统性能监测工具-项目介绍与各工具使用方法 |
| Systems_Performance_Network.md | 《性能之巅》网络子系统相关部分阅读笔记 |
| notes | 开发过程中遇到的问题与解决方案 | 
| apply | GitLink项目介绍与申请方案 |


计划完成的文档
| doc | content |
| ------ | ------ |
| performance_monitoring | 根据性能检测法监测网络子系统 |
| interface | 网络接口层源码分析，传统工具VSeBPF |
| tcp | tcp层源码分析，传统工具VSeBPF | 

