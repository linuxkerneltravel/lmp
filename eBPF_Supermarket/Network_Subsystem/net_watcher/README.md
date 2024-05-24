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
`netwatcher`是一款基于eBPF的高效网络检测工具，其目的是为了让用户能够轻松快捷地获取到网络协议栈的详细信息，通过高效的数据采集和精准的监控能力，帮助用户深入了解网络行为，确保网络安全和性能的优化。其在车辆智能导航、自动驾驶等关键领扮演着重要角色，面对网络异常或延迟时，`netwatcher`能够提供强大的网络监测和优化支持，帮助企业及时诊断并解决网络障碍，提升系统稳定性和服务可靠性。

netwatcher作为一款基于eBPF的网络检测工具，其设计初衷是帮助用户能够在主机环境中，轻松快捷地获取到 Linux 网络协议栈的详细信息，通过高效的数据收集和精准的监控能力，深入了解网络行为，确保网络安全和性能的优化，其应用范围涉及较广。

netwatcher能够追踪TCP、UDP、ICMP协议数据包从应用程序发出开始，经过内核协议栈到驱动、最终发出过程（发包路径）的时延数据和流量信息，以及数据包从驱动到内核协议栈到用户态程序的过程（收包路径）中的时延数据。对获取到的时延数据采用算法进行阈值比较捕获异常时延数据并给予警告信息。同时监测TCP连接的状态信息（seq、ack、连接状态、重传信息、错误信息、rwnd、cwnd、sndbuf等关键指标），并且可以监控丢包事件（包括skb_drop_reason中定义的77种原因）。

其有助于及时解决各种网络问题，提高系统稳定性和服务可靠性。无论是云计算所需要的确保其基础设施的稳定性和安全性，还是金融机构需要保障交易的及时性和安全性，亦或是电子商务企业追求用户体验和网站性能的优化，netwatcher都提供了强大的网络监测和优化能力，满足不同行业的需求，助力企业顺利应对数字化时代的挑战。

目前，其实现的功能包括：

- TCP相关的信息监测：主机环境下对tcp/ip协议的分析，可以统计流量，延时，错误，链接信息等主要信息
- HTTP1/1.1相关信息检测：通过截取相应TCP包的HTTP头实现主机环境下对用户态http1的分析
- TCP、UDP、ICMP相关信息监测：追踪TCP、UDP、ICMP协议数据包，并实现对主机接收和发送的所有相关数据包的时延数据和流量信息
- 监测TCP连接状态信息：包括三次握手以及四次挥手的状态转变和时延数据
- 丢包事件的监控：分析导致丢包的地址以及丢包原因

#### TODO
- [ ] 应用层协议的支持
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
- doc/:
  - implement.md：详细描述本项目的实现细节
- data/：文件夹存放打印的日志信息
  - connects.log：符合Prometheus格式的连接信息
  - err.log：符合Prometheus格式的错误包信息
  - packets.log：符合Prometheus格式的包信息
- udp.loh：符合Prometheus格式的udp包信息
- visual.py：暴露metrics接口给Prometheus，输出data文件夹下的所有信息
- netwatcher.c ：对bpf.c文件中记录的信息进行输出
- netwatcher.bpf.c：封装内核探针点。
- tcp.bpf.h：网络数据包处理以及tcp连接状态等信息具体实现细节。
- udp.bpf.h ：udp数据包时延、流量的具体处理逻辑。
- packet.bpf.h ：网络数据包的处理、时间戳的记录、数据包信息的提取等指标具体处理逻辑。
- netfilter.bpf.h：处理netfilter时延的具体逻辑，`submit_nf_time`函数将时延信息提交到用户态，`store_nf_time`函数存储经过每个`HOOK`点的时延。
- drop.bpf.h ：数据包丢弃原因的具体处理逻辑。
- dropreason.h ：skb_drop_reason定义77种丢包原因。
- icmp.bpf.h： icmp时延具体实现细节。
- comm.bpf.h ：辅助函数、宏、BPF映射、以及内核中使用到的结构体。

## 二、快速开始
### 2.1 安装依赖
OS: Ubuntu 22.04LTS

Kernel：Linux 6.2

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
- 指定`-e`参数会记录SEQ错误或Checksum错误的TCP包并输出到标准输出以及data/err.log中。
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
    - 连接总重传次数。
- 指定 `-i` 参数监控HTTP信息。从携带HTTP请求头的TCP包中将HTTP请求头提取并输出，记录HTTP的状态码等信息。
- 指定 `-u` 参数监控UDP数据包信息。统计UDP协议的数据包流量、以us为单位的时延等信息。
- 指定 `-n` 参数监控ipv4网络层的Netfilter延迟。监测ipv4网络层数据包经过Netfilter各个HOOK点的处理时延。
- 指定 `-k` 参数监测系统中的各类丢包并分析丢包原因，详细定位协议丢包的指令地址。
- 指定 `-S` 参数监控TCP的连接状态以及状态转换的时延。
- 指定 `-I` 参数监控ICMP协议数据包收发过程中的时延。
- 指定 `-T` 参数将捕获到的丢包事件虚拟地址转换成函数名+偏移量形式。
- 指定 `-L` 参数监测网络协议栈数据包经过各层的时延，采用指数加权移动法对异常的时延数据进行监控并发出警告信息。

### 3.1 监控连接信息
`netwatcher`会将保存在内存中的连接相关信息实时地在`data/connects.log`中更新。默认情况下，为节省资源消耗，`netwatcher`会实时删除已CLOSED的TCP连接相关信息，并只会保存每个TCP连接的基本信息。
```c
// data/connects.log
connection{pid="44793",sock="0xffff9d1ecb3ba300",src="10.0.2.15:46348",dst="103.235.46.40:80",is_server="0",backlog="-",maxbacklog="-",cwnd="-",ssthresh="-",sndbuf="-",wmem_queued="-",rx_bytes="-",tx_bytes="-",srtt="-",duration="-",total_retrans="-",fast_retrans="-",timeout_retrans="-"} 
```
#### 3.1.1 保留所有连接信息
对于想要保留所有连接信息的用户，需要指定`-a`参数。
```
sudo ./netwatcher -a
```
#### 3.1.2 监控额外连接信息
`netwatcher`指定`-x`参数输出额外信息 ，额外信息实时更新于data/connects.log日志中。记录接收窗口大小rwnd、拥塞窗口大小cwnd、慢启动阈值ssthresh、发送缓冲区大小sndbuf、已使用的发送缓冲区wmem_queued、已接收字节数rx_bytes、已确认字节数tx_bytes、平滑往返时间srtt、连接建立时延duration等关键信息。

```c
sudo ./netwatcher -x   
connection{pid="45395",sock="0xffff9780c13f7500",src="192.168.60.136:42938",dst="171.214.23.48:443",is_server="0",backlog="0",maxbacklog="0",rwnd="63986",cwnd="10",ssthresh="2147483647",sndbuf="87040",wmem_queued="0",rx_bytes="603",tx_bytes="1.563K",srtt="68166",duration="63879",total_retrans="0",fast_retrans="-",timeout_retrans="-"}
```
#### 3.1.3 监控重传信息
`netwatcher`监控超时重传次数、快速重传次数和连接总重传次数，指定`-r`参数。

```c
sudo ./netwatcher -r
connection{pid="45395",sock="0xffff9780c13f6c00",src="192.168.60.136:60210",dst="124.237.208.55:443",is_server="0",backlog="0",maxbacklog="0",rwnd="63784",cwnd="10",ssthresh="2147483647",sndbuf="87040",wmem_queued="0",rx_bytes="568",tx_bytes="8.489K",srtt="65211",duration="319696",total_retrans="0",fast_retrans="-",timeout_retrans="2"}
```
### 3.2 监控包信息
`netwatcher`会将各个TCP包的相关信息实时地输出在标准输出以及`data/packets.log`中。默认情况下，为节省资源消耗，`netwatcher`只会监控各个包的基本信息并输出。

```c
sudo ./netwatcher
SOCK                   SEQ        ACK        MAC_TIME   IP_TIME    TCP_TIME   RX   HTTP
0xffff9d1ecb3ba300     629372796  279168002  -          -          -          0     -
0xffff9d1ecb3ba300     279168002  629372873  -          -          -          1     -
```
```c
// data/packets.log
packet{sock="0xffff9d1ecb3ba300",seq="629372796",ack="279168002",mac_time="-",ip_time="-",tcp_time="-",http_info="-",rx="0"} 
packet{sock="0xffff9d1ecb3ba300",seq="279168002",ack="629372873",mac_time="-",ip_time="-",tcp_time="-",http_info="-",rx="1"} 
```
#### 3.2.1监控数据包在各层的处理时延
`netwatcher`监控各个数据包在各层的处理时间，指定`-t`参数，`netwatcher`会输出以`us`为单位的各层处理时间，支持ipv4、ipv6协议。

```c
sudo ./netwatcher -t   
SOCK                 SEQ        ACK        MAC_TIME   IP_TIME    TRAN_TIME  RX    HTTP
0xffffa069b1271200   3401944293 1411917682 4          15         15         0     -
0xffffa06982943600   537486036  4194537197 16         14         123        1     -
0xffffa06982943600   537486036  4194537197 16         14         130        1     -
0xffffa06982946c00   3341452281 1920160519 3          13         12         0     -
```

指定参数`-u`，查看UDP数据包处理时延并记录于`data/udp.log`中，单位为微妙。

```c
sudo ./netwatcher -u
saddr         daddr          sprot    dprot     udp_time     rx          len    
192.168.60.2  192.168.60.136 38151    53        7            1            119
192.168.60.2  192.168.60.136 36524    53        5            1            89 
```

指定参数`-I`，查看ICMP数据包处理时延，单位为微妙。

```c
sudo ./netwatcher -I
saddr          daddr              time     flag             
192.168.60.136 192.168.60.136     11        1  
192.168.60.136 192.168.60.136     5         0  
192.168.60.136 192.168.60.136     80        1  
```

指定参数`-n`，查看数据包在Netfilter框架（包括PRE_ROUTING、LOCAL_IN、FORWARD、LOCAL_OUT、POST_ROUTING链中处理的时间），单位为微妙，其网络数据包路径为：

- 发往本地：**NF_INET_PRE_ROUTING**-->**NF_INET_LOCAL_IN**
- 转发：**NF_INET_PRE_ROUTING**-->**NF_INET_FORWARD**-->**NF_INET_POST_ROUTING**
- 本地发出：**NF_INET_LOCAL_OUT**-->**NF_INET_POST_ROUTING**

```c
sudo ./netwatcher -n
saddr          daddr        dprot  sprot   PreRT  L_IN  FW   PostRT  L_OUT    rx      
192.168.60.136 192.168.60.1 22     51729   0      0     0    2        3        0       
192.168.60.136 192.168.60.1 22     51729   0      0     0    1        3        0       
127.0.0.1      127.0.0.1    771    10787   2      2     0    0        0        1
127.0.0.1      127.0.0.1    771    15685   2      2     0    0        0        1   
```

#### 3.2.2 监控错误数据包

`netwatcher`提供对TCP错误的监控支持，用户只需指定`-e`参数，`netwatcher`会记录SEQ错误或Checksum错误的TCP包并输出到标准输出以及`data/err.log`中。

```c
sudo ./netwatcher -e  
packet{sock="0xffff13235ac8ac8e",seq="1318124482",ack="2468218244",reason="Invalid SEQ"}
```

#### 3.2.3 HTTP1/1.1
`netwatcher`提供对HTTP1/1.1信息的监控，在指定`-i`参数后，`netwatcher`会从携带HTTP请求头的TCP包中将HTTP请求头提取并输出，提取信息包括包含请求资源方式、状态码、状态文本等。

```c
sudo ./netwatcher -i
SOCK                   SEQ        ACK        MAC_TIME   IP_TIME    TCP_TIME   RX    HTTP
0xffff9d1ecb3b9180     3705894662 522176002  -          -          -          0     GET / HTTP/1.1
0xffff9d1ecb3b9180     522176002  3705894739 -          -          -          1     HTTP/1.1 200 OK
```

#### 3.2.3 过滤指定目的端口、源端口

```c
sudo ./netwatcher -d 80 或者 sudo ./netwatcher -s 80
```

#### 3.2.4 TCP协议数据包连接状态

指定参数`-S`，对TCP数据包连接状态的监控。netwatcher会跟踪TCP连接状态的转换，其中可以对各个状态所持续的时间进行监测。

```C
sudo ./netwatcher -S   
saddr            daddr     sport    dport   oldstate    newstate      time  
192.168.60.136   1.1.1.1   41586    80      FIN_WAIT1   FIN_WAIT2     386             
192.168.60.136   1.1.1.1   41586    80      FIN_WAIT2   CLOSE         19  
```

#### 3.2.5 捕捉丢包及原因

指定参数`-k`，捕捉丢包信息并获取其导致丢包的函数地址、丢包原因。

```c
sudo ./netwatcher -k
time      saddr      daddr     sprot   dprot   prot    addr                     
reason    
14:45:11  127.0.0.1  127.0.0.1 51162   36623   ipv4    ffffffff920fbf89       SKB_DROP_REASON_TCP_OLD_DATA
```

指定参数`-T`，可以将虚拟地址转换成函数名+偏移的形式，在此处可以捕捉发生丢包的内核函数名称。 

```C
sudo ./netwatcher -k -T
time      saddr           daddr          sprot   dprot  prot  addr                     reason                        
14:48:54  192.168.60.136  192.168.60.136 45828   8090   ipv4  tcp_v4_rcv+0x84         SKB_DROP_REASON_NO_SOCKET
14:49:04  118.105.115.105 110.103.32.49  26210   24435  other unix_dgram_sendmsg+0x521 SKB_DROP_REASON_NOT_SPECIFIED
```

#### 3.2.7 异常时延监控

对获取到的各层时延加上-L参数进行监控，捕获监测到的异常数据并给予警告信息。

```C
sudo ./netwatcher -t -L
saddr     daddr       sprot    dprot   udp_time     rx       len     
127.0.0.1 127.0.0.53  44530    53      1593         0        51      abnoermal data
```

### 3.3 与Prometheus连接进行可视化

`data`目录下的所有文件都满足Prometheus要求的时序数据库格式。`netwatcher`使用`visual.py`在端口41420暴露`metrics`API为Prometheus提供可视化支持，当Prometheus请求此API时，会获得当前时刻所有log文件的全部内容。由于log文件被eBPF程序实时更新，因此满足时序性。
```c
python visual.py
```
## 四、代码实现细节
- 详细实现细节见`doc/implement.md`
