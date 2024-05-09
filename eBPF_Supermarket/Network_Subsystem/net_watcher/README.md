# netwatcher - 网络检测工具
## 一、工具介绍
### 1.1 背景

lmp现有许多用于监控linux网络协议栈相关信息的小工具，但这些工具功能零散并且冗余：
| 工具目录 | 功能 | 监控信息 |
| --- | --- | --- |
| old/delay_analysis | 分析各个TCP数据包在各层的处理时间 | **四元组**，**ACK**、**SEQ**，**各层处理时间** |
| old/tcp_backlog | 获取sock的全连接队列信息 | 当前全连接队列长度：**sk_ack_backlog**，全连接队列最大长度：**sk_max_ack_backlog** |
| old/tcp_bytes | 获取每个TCP连接接收和发送的数据量 | **PID**、**COMMAND**、**四元组**、**RX_KB**、**TX_KB** |
| old/tcp_connection | 输出每个TCP连接的信息 | 连接建立的时间戳、**PID**、**COMMAND**、**四元组**、**连接方向** |
| old/tcp_inerrs | 输出TCP错误包信息，包含以下错误：seq错误、checksum错误 | 时间戳、**PID**、**COMMAND**、**四元组**、**错误原因**、连接状态 |
| old/tcp_win | 监控TCP窗口相关信息 | **四元组**、**拥塞窗口大小**、**慢启动阈值**、**发送缓冲区大小**、**已使用发送缓冲区大小** |
| old/tcp_flow | 监控TCP流相关信息 | **pid**、**四元组**、连接状态、tcpflags、**拥塞窗口大小**、**接收窗口大小**、**bytes_acked**、**bytes_received**、**total_retrans**（连接重传总次数）、**srtt**、**fastRe**（快速重传次数）、**timeout**（重传定时器到时次数）、packets_out（未被确认的包数）、bytes_inflight（未被确认的字节数）、**duration**（TCP流已存在时间） |
| old/congestion/all_delay_detect | 监控socket srtt相关信息 | **srtt**、mdev_us（srtt 平均方差） |
| old/congestion/all_delay_detect | 监控tcp拥塞状态 | icsk_ca_state |

在此背景下，本工具通过整合目录`../old`下已有eBPF小工具，通过选取一些**核心信息（上表中加粗）**，在主机空间实现linux网络协议栈的监控。


### 1.2 功能介绍
`netwatcher`是一款基于eBPF的网络检测工具，其旨在使用户方便快捷的获取主机环境下linux网络协议栈的各种信息。

netwatcher作为一款基于eBPF的网络检测工具，其设计初衷是帮助用户能够在主机环境中，轻松快捷地获取到 Linux 网络协议栈的详细信息，通过高效的数据收集和精准的监控能力，深入了解网络行为，确保网络安全和性能的优化，其应用范围涉及较广。

netwatcher能够追踪TCP、UDP、ICMP协议数据包从应用程序发出开始，经过内核协议栈到驱动、最终发出过程（发包路径）的时延数据和流量信息，以及数据包从驱动到内核协议栈到用户态程序的过程（收包路径）中的时延数据。对获取到的时延数据采用算法进行阈值比较捕获异常时延数据并给予警告信息。同时监测TCP连接的状态信息（seq、ack、连接状态、重传信息、错误信息、rwnd、cwnd、sndbuf等关键指标），并且可以监控丢包事件（包括skb_drop_reason中定义的77种原因）。

其有助于及时解决各种网络问题，提高系统稳定性和服务可靠性。无论是云计算所需要的确保其基础设施的稳定性和安全性，还是金融机构需要保障交易的及时性和安全性，亦或是电子商务企业追求用户体验和网站性能的优化，netwatcher都提供了强大的网络监测和优化能力，满足不同行业的需求，助力企业顺利应对数字化时代的挑战。

目前，其实现的功能包括：
- TCP相关的信息监测：主机环境下对tcp/ip协议的分析，可以统计流量，延时，错误，链接信息等主要信息
- HTTP1/1.1相关信息检测：通过截取相应TCP包的HTTP头实现主机环境下对用户态http1的分析

#### TODO
- [ ]  ICMP数据包信息的监控
    - 实现对ICMP协议报文的监控，输出到达的ICMP数据包的消息类型
- [ ]  UDP数据包信息的监控
    - 实现对主机接收和发送的所有UDP数据包的监控，输出各个UDP数据包的地址-端口4元组
- [ ]  应用层协议的支持
    - 在各个底层协议之上，提供对以下应用层信息的监控
    - [ ]  HTTP协议相关
        - [ ]  HTTP1
            - 目前已实现对请求头的抽取与监控，在此之上实现HTTP1请求体的全面解析
        - [ ]  HTTP2
            - 考虑使用user probe，实现对HTTP2协议头信息的监控，包括请求方法、状态码、头字段等
        - [ ]  HTTP3（QUIC）
            - 在UDP的基础上，实现对QUIC协议信息的监控，包括连接ID、各个数据包的唯一序号，各个流的流标识等
    - [ ]  Redis (REPS)
        - 实现对Redis相关信息的抽取与监控，包括REPS数据，错误信息等
    - [ ]  MySQL
        - 实现对MySQL报文中相关信息的监控，包括认证交互报文、客户端命令请求报文与服务器响应报文
    - [ ]  DNS
        - 实现对DNS协议报文相关信息的监控，并可提供DNS代理功能


### 1.3 组织结构

- netwatcher.bpf.c：将相应程序挂载到函数上
- netwatcher.c: 对bpf.c文件中记录的信息进行输出
- netwatcher.h: 定义内核态与用户态程序共用的结构体
- common.bpf.h 定义了一些数据包头部之间转换的辅助函数、宏、BPF映射、以及内核中使用到的结构体
- tcp.bpf.h 网络数据包处理以及连接状态等信息具体实现细节
- udp.bpf.h udp数据包收发过程时延、流量的具体处理逻辑
- packet.bpf.h 封装了一系列与网络数据包的处理、时间戳的记录、数据包信息的提取等相关函数
─ icmp.bpf.h  icmp数据包收发包时延具体实现细节
- netfilter.bpf.h 封装了处理网络过滤器netfilter时延的具体逻辑，submit_nf_time函数用于将时延信息提交到用户态，而store_nf_time函数则用于存储经过每个HOOK点的时延。
- drop.bpf.h 数据包丢弃原因的具体处理逻辑
- dropreason.h 字符串数组描述数据包可能丢弃的各种原因
- lib/:  基于的libbpf库、bpftool以及vmlinux
- doc/:
  - implement.md：详细描述本项目的实现细节
- data/：文件夹存放打印的日志信息
  - connects.log：符合Prometheus格式的连接信息
  - err.log：符合Prometheus格式的错误包信息
  - packets.log：符合Prometheus格式的包信息
  - netfilter.log：符合Prometheus格式的netfilter信息
- visual.py：暴露metrics接口给Prometheus，输出data文件夹下的所有信息


## 二、快速开始
### 2.1 安装依赖
OS: Ubuntu 22.04LTS
```bash
sudo apt update
sudo apt install libbpf-dev clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
git submodule update --init --recursive
```
- 本工具依赖于`libbpf-bootstrap`项目，请确保其在同级目录下
### 2.2 编译运行
```bash
sudo apt insatll bear && bear -- make # 用以生成clang的编译数据库，以供clang-lint使用
make # 如果不需要clang编译数据库，则直接make
sudo ./netwatcher [options] # 运行
sudo make test # 测试
```
## 三、使用方法
`netwatcher`通过一系列命令参数来控制其具体行为：

```bash
Usage: netwatcher [OPTION...]
Watch tcp/ip in network subsystem
  -a, --all                  set to trace CLOSED connection
  -d, --dport=DPORT          trace this destination port only
  -e, --err                  set to trace TCP error packets
  -i, --http                 set to trace http info
  -I, --icmptime             set to trace layer time of icmp
  -k, --drop_reason          trace kfree 
  -L, --timeload             analysis time load
  -n, --net_filter           trace ipv4 packget filter 
  -r, --retrans              set to trace extra retrans info
  -s, --sport=SPORT          trace this source port only
  -S, --tcpstate             set to trace tcpstate
  -t, --time                 set to trace layer time of each packet
  -T, --addr_to_func         translation addr to func and offset
  -u, --udp                  trace the udp message
  -x, --extra                set to trace extra conn info
  -?, --help                 Give this help list
```
- 参数`-d`,`-s`用于指定监控某个源端口/目的端口
- 指定参数`-a`会保留已CLOSED的TCP连接信息
- 指定`-e`参数会记录SEQ错误或Checksum错误的TCP包
- 默认情况下，监控以下连接信息与包信息：
    - TCP连接pid
    - TCP连接\[源地址:端口,目的地址:端口\]
    - TCP连接sock地址
    - TCP连接方向（是否为TCP Server）
    - TCP包sock地址（用于明确TCP连接）
    - TCP包ack
    - TCP包seq
- 指定`-t`参数会监控各个包在每一层的处理时间，单位us
- 指定`-r`参数会监控快速重传与超时重传次数
- 指定`-x`参数会监控以下额外连接信息：
    - backlog
    - max_backlog
    - 已确认的字节数
    - 已接收的字节数
    - 拥塞窗口大小
    - 慢启动阈值
    - 发送缓冲区大小
    - 已使用的发送缓冲区
    - 平滑往返时间
    - 连接已建立时长
    - 连接总重传次数
### 3.1 监控连接信息
`netwatcher`会将保存在内存中的连接相关信息实时地在`data/connects.log`中更新。默认情况下，为节省资源消耗，`netwatcher`会实时删除已CLOSED的TCP连接相关信息，并只会保存每个TCP连接的基本信息。
```
// data/connects.log
connection{pid="44793",sock="0xffff9d1ecb3ba300",src="10.0.2.15:46348",dst="103.235.46.40:80",is_server="0",backlog="-",maxbacklog="-",cwnd="-",ssthresh="-",sndbuf="-",wmem_queued="-",rx_bytes="-",tx_bytes="-",srtt="-",duration="-",total_retrans="-",fast_retrans="-",timeout_retrans="-"} 0
```
#### 3.1.1 保留所有连接信息
对于想要保留所有连接信息的用户，需要指定`-a`参数。
```
sudo ./netwatcher -a
```
#### 3.1.2 监控额外连接信息
`netwatcher`默认只监控基本连接信息，额外连接信息输出为`-`；对于想要监控额外连接信息的用户，需要指定`-x`参数。
```
sudo ./netwatcher -x
```
#### 3.1.3 监控重传信息
`netwatcher`监控的额外连接信息并不提供对超时重传次数与快速重传次数的细化；对于想要获取此信息的用户，需要指定`-r`参数。
```
sudo ./netwatcher -r
```
### 3.2 监控包信息
`netwatcher`会将各个TCP包的相关信息实时地输出在标准输出以及`data/packets.log`中。默认情况下，为节省资源消耗，`netwatcher`只会监控各个包的基本信息并输出。
```
sudo ./netwatcher
SOCK                   SEQ        ACK        MAC_TIME   IP_TIME    TCP_TIME   RX    HTTP
0xffff9d1ecb3ba300     629372796  279168002  -          -          -          0     -
0xffff9d1ecb3ba300     279168002  629372873  -          -          -          1     -
```
```
// data/packets.log
packet{sock="0xffff9d1ecb3ba300",seq="629372796",ack="279168002",mac_time="-",ip_time="-",tcp_time="-",http_info="-",rx="0"} 0
packet{sock="0xffff9d1ecb3ba300",seq="279168002",ack="629372873",mac_time="-",ip_time="-",tcp_time="-",http_info="-",rx="1"} 0

```
#### 3.2.1 各层处理时间
`netwatcher`提供监控各个数据包在各层的处理时间的支持。为了获得这部分信息，用户需要指定`-t`参数，`netwatcher`会输出以`us`为单位的各层处理时间。
```
sudo ./netwatcher -t
SOCK                   SEQ        ACK        MAC_TIME   IP_TIME    TCP_TIME   RX    HTTP
0xffff9d1ec43fd780     2018346083 420544002  1          3          9          0     -
0xffff9d1ec43fd780     420544002  2018346160 67         12         494        1     -
0xffff9d1ec43fd780     420545414  2018346160 40         5          258        1     -
```

#### 3.2.2 监控错误数据包
`netwatcher`提供对TCP错误的监控支持，用户只需指定`-e`参数，`netwatcher`会记录SEQ错误或Checksum错误的TCP包并输出到标准输出以及`data/err.log`中。
```
sudo ./netwatcher -e
```

#### 3.2.3 HTTP1/1.1
`netwatcher`提供对HTTP1/1.1信息的监控，在指定`-i`参数后，`netwatcher`会从携带HTTP请求头的TCP包中将HTTP请求头提取并输出。
```
sudo ./netwatcher -i
SOCK                   SEQ        ACK        MAC_TIME   IP_TIME    TCP_TIME   RX    HTTP
0xffff9d1ecb3b9180     3705894662 522176002  -          -          -          0     GET / HTTP/1.1
0xffff9d1ecb3b9180     522176002  3705894739 -          -          -          1     HTTP/1.1 200 OK
```

### 3.3 与Prometheus连接进行可视化
可以注意到，`data`中的所有文件都满足Prometheus要求的时序数据库格式。`netwatcher`使用`visual.py`在端口41420暴露`metrics`API为Prometheus提供可视化支持，当Prometheus请求此API时，会获得当前时刻下三个log文件的所有内容。由于三个log文件被eBPF程序实时更新，因此满足时序性。
```
python visual.py
```
## 四、代码实现细节
- 见`doc/implement.md`