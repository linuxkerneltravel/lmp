# 基于eBPF的Linux系统性能监测工具-网络子系统

## 0. 介绍

本目录基于eBPF机制对Linux系统网络子系统关键性能参数进行监测。

bpftrace_application 是一些 Bpftrace 构建的例程，需要预装 bpftrace，其特点是代码简单，能很快上手，缺点是不能支撑高复杂性的 eBPF 应用。

其余以 go_ 开头的各个文件夹是用 go语言 + eBPF 构建的eBPF例程，使用了开源的cilium/eBPF库，可以支撑高复杂性、模块化的 eBPF 应用。

## 1. 准备工作

开发环境
* 系统：Debian GNU/Linux 11
* 内核：5.10.0-13-amd64
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
    [可选] 输出时间间隔，默认为1s

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

### 2.2 tcp_connection

实时输出成功建立的tcp连接，输出包括时间、进程号、进程名称、IPv4/IPv6、目标ip、目标端口、源ip、源端口、方向（connect/accept）。

参数如下：
```
-p，--pid
    [可选] 指定进程
-P, --port
    [可选] 指定源端口
-r, --direction
    [可选] 仅输出方向为connect或accept的连接
-4, --ipv4
    [可选] 仅输出IPv4连接
-6, --ipv6
    [可选] 仅输出IPv6连接


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

### 2.3 tcp_bytes

按指定的时间间隔输出不同TCP进程发送与接收的字节数，输出包括进程号、进程名称、源ip：端口、目标ip：端口、接收KB、发送KB。

参数如下：
```
-p，--pid
    [可选] 指定进程
-i, --interval
    [可选] 输出时间间隔，默认为1s
-4, --ipv4
    [可选] 仅输出IPv4连接
-6, --ipv6
    [可选] 仅输出IPv6连接

```

运行示例 
``` shell
sudo python tcptop           # trace TCP send/recv by host
    ./tcptop -C        # don't clear the screen
    ./tcptop -p 181    # only trace PID 181
    ./tcptop --cgroupmap mappath  # only trace cgroups in this BPF map
    ./tcptop --mntnsmap mappath   # only trace mount namespaces in the map
    ./tcptop -4        # trace IPv4 family only
    ./tcptop -6        # trace IPv6 family only
```

输出样例
``` shell
Thu Aug  4 21:23:28 2022
PID     COMM         SADDR                 DADDR                  RX_KB  TX_KB
3224405 b'sshd'      166.111.226.109:22    101.5.230.37:62037         0     40
4022997 b'sshd'      166.111.226.109:2222  166.111.80.116:6058        0      0

PID     COMM         SADDR6                                   DADDR6                                    RX_KB  TX_KB
2249878 b'gitlab-run 2402:f000:4:1001:809:26d1:ae03:a462:42774 2402:f000:1:408:101:6:8:149:443               0      0
2249878 b'gitlab-run 2402:f000:4:1001:809:26d1:ae03:a462:42778 2402:f000:1:408:101:6:8:149:443               0      0
```

### 2.4 tcp_inerrs

实时输出所有收到的有问题的TCP包数量，输出包括时间、进程号、进程名称、IPv4/IPv6、源ip：端口、目标ip：端口、问题原因、tcp连接状态。


参数如下：
```
-p，--pid
    [可选] 指定进程
-4, --ipv4
    [可选] 仅输出IPv4连接
-6, --ipv6
    [可选] 仅输出IPv6连接

```

运行示例 
``` shell
sudo python tcp_inerrs.py           # trace TCP send/recv by host
sudo python tcp_inerrs.py -p 181    # only trace PID 181
sudo python tcp_inerrs.py -4        # trace IPv4 family only
sudo python tcp_inerrs.py -6        # trace IPv6 family only
```

输出样例
``` shell
TIME      PID     COMM         IP SADDR:SPORT              > DADDR:DPORT              REASON       STATE
21:14:36  0       swapper/7    6  ::ffff:10.85.1.5:1717    > ::ffff:10.85.1.5:55596   invalid seq  ESTABLISHED
21:14:36  68      ksoftirqd/11 6  ::ffff:10.85.1.5:1717    > ::ffff:10.85.1.5:55592   invalid seq  ESTABLISHED
21:14:36  0       swapper/22   6  ::ffff:10.85.1.5:55598   > ::ffff:10.85.1.5:1717    invalid seq  ESTABLISHED
21:14:36  0       swapper/22   6  ::ffff:10.85.1.5:55596   > ::ffff:10.85.1.5:1717    invalid seq  ESTABLISHED
21:14:36  0       swapper/22   6  ::ffff:10.85.1.5:55592   > ::ffff:10.85.1.5:1717    invalid seq  ESTABLISHED
```

不足

inerrs的统计目前只统计了tcp_validate_incoming的seq，tcp_v4_do_rcv和tcp_v6_do_rcv中包长度与TCP header比较及skb_checksum_complete，但缺少tcp_v4_rcv和tcp_v6_rcv中的部分验证。



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

