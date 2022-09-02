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
sudo python tcp_connection.py -P 80,81  # only trace port 80 and 81
sudo python tcp_connection.py -p 181    # only trace PID 181
sudo python tcp_connection.py -4        # only trace IPv4 family
sudo python tcp_connection.py -6        # only trace IPv6 family
sudo python tcp_connection.py -r accept # only trace accept tcp connections
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
sudo python tcp_bytes.py           # trace TCP send/recv bytes by host
sudo python tcp_bytes.py -p 181    # only trace PID 181
sudo python tcp_bytes.py -i 5      # print results every 5 seconds
sudo python tcp_bytes.py -4        # trace IPv4 family only
sudo python tcp_bytes.py -6        # trace IPv6 family only
```

输出样例
``` shell
Thu Aug  4 21:23:28 2022
PID     COMM         SADDR                 DADDR                  RX_KB  TX_KB
3224405 b'sshd'      xxx.xxx.226.109:22    101.5.230.37:62037         0     40
4022997 b'sshd'      xxx.xxx.226.109:2222  xxx.xxx.80.116:6058        0      0

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

不足:

inerrs的统计目前只统计了tcp_validate_incoming的seq，tcp_v4_do_rcv和tcp_v6_do_rcv中包长度与TCP header比较及skb_checksum_complete，但缺少tcp_v4_rcv和tcp_v6_rcv中的部分验证。


### 2.5 delay_analysis_in/delay_analysis_in_v6

实时输出所有接收包信息及内核各层处理过程所花费的时间。


参数如下：
```
-sp，--sport
    [可选] 指定源端口
-dp, --dport
    [可选] 指定目标端口
-s, --sample
    [可选] 随机选包进行输出

```

运行示例 
``` shell
sudo python delay_analysis_in.py           # in packets delay analysis
sudo python delay_analysis_in.py -dp 181   # only trace dport 181
sudo python delay_analysis_in.py -s        # print random packets
```

输出样例-ipv4
``` shell
SADDR:SPORT            -> DADDR:DPORT            SEQ          ACK          TIME                 TOTAL      MAC        IP         TCP
xxx.xxx.80.116:5622    -> xxx.xxx.226.109:2222   2064211175   1609909874   9107651.969982       86         5          12         68
127.0.0.1:44768        -> 127.0.0.1:45707        1556586908   600876255    9107651.970152       52         4          4          43
127.0.0.1:45707        -> 127.0.0.1:44768        600876255    1556586938   9107651.972246       36         3          3          28
```

输出样例-ipv6
``` shell
SADDR:SPORT                        -> DADDR:DPORT                            SEQ          ACK          TIME                 TOTAL      MAC        IP         TCP
2402:f000:xx:xx:xx:xx:8:149:443    -> 2402:f000:xx:xx:xx:xx:ae03:a462:40512  3945336401   1159424513   9544853.614323       49         2          2          45
2402:f000:xx:xx:xx:xx:8:149:443    -> 2402:f000:xx:xx:xx:xx:ae03:a462:40260  1111257592   1393462606   9544854.102531       65         1          1          61
2402:f000:xx:xx:xx:xx:8:149:443    -> 2402:f000:xx:xx:xx:xx:ae03:a462:40270  1152750621   2984387336   9544854.631066       75         4          4          66
2402:f000:xx:xx:xx:xx:8:149:443    -> 2402:f000:xx:xx:xx:xx:ae03:a462:40452  1185853100   1593078888   9544855.197227       69         6          4          58
```


### 2.6 delay_analysis_out/delay_analysis_out_v6

实时输出所有发送包信息及内核各层处理过程所花费的时间。


参数如下：
```
-sp，--sport
    [可选] 指定源端口
-dp, --dport
    [可选] 指定目标端口
-s, --sample
    [可选] 随机选包进行输出

```

运行示例 
``` shell
sudo python delay_analysis_out.py           # in packets delay analysis
sudo python delay_analysis_out.py -dp 181   # only trace dport 181
sudo python delay_analysis_out.py -s        # print random packets
```

输出样例-ipv4
``` shell
SADDR:SPORT            -> NAT:PORT               -> DADDR:DPORT            SEQ          ACK          TIME                 TOTAL      QDisc      IP         TCP
xxx.xxx.226.109:2222   -> xxx.xxx.226.109:2222   -> xxx.xxx.80.116:6119    454627680    4175823286   9107735153635.615234 7          1          4          1
xxx.xxx.226.109:2222   -> xxx.xxx.226.109:2222   -> xxx.xxx.80.116:6119    454627884    4175823286   9107735153671.039062 4          0          2          0
xxx.xxx.226.109:2222   -> xxx.xxx.226.109:2222   -> xxx.xxx.80.116:6119    454628256    4175823286   9107735153707.218750 3          0          2          0
xxx.xxx.226.109:2222   -> xxx.xxx.226.109:2222   -> xxx.xxx.80.116:6119    454628664    4175823286   9107735153770.941406 9          1          7          1
```

输出样例-ipv6
``` shell
SADDR:SPORT                            -> DADDR:DPORT                      SEQ          ACK          TIME                 TOTAL      QDisc      IP         TCP
2402:f000:xx:xx:xx:xx:ae03:a462:40452  -> 2402:f000:xx:xx:xx:xx:8:149:443  1593144414   1185882612   9545059296177.548828 20         3          11         4
2402:f000:xx:xx:xx:xx:ae03:a462:40452  -> 2402:f000:xx:xx:xx:xx:8:149:443  1593145392   1185883046   9545059358555.283203 13         2          7          3
2402:f000:xx:xx:xx:xx:ae03:a462:40468  -> 2402:f000:xx:xx:xx:xx:8:149:443  68187760     42173401     9545059796634.861328 12         1          7          2
2402:f000:xx:xx:xx:xx:ae03:a462:40468  -> 2402:f000:xx:xx:xx:xx:8:149:443  68188738     42173835     9545060000960.453125 9          1          4          2
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

