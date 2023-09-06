# netwatch - 网络检测工具
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
`netwatch`是一款基于eBPF的网络检测工具，其旨在使用户方便快捷的获取主机环境下linux网络协议栈的各种信息。目前，其实现的功能包括：
- TCP相关的信息监测：主机环境下对tcp/ip协议的分析，可以统计流量，延时，错误，链接信息等主要信息
- HTTP1/1.1相关信息检测：通过截取相应TCP包的HTTP头实现主机环境下对用户态http1的分析

### 1.3 组织结构
- netwatch.bpf.c：在各个内核探针点对TCP包信息、TCP连接信息以及各个包的HTTP1/1.1信息进行记录
- netwatch.c: 对bpf.c文件中记录的信息进行输出
- netwatch.h: 定义内核态与用户态程序共用的结构体
- doc/:
  - implement.md：详细描述本项目的实现细节
- data/：
  - connects.log：符合Prometheus格式的连接信息
  - err.log：符合Prometheus格式的错误包信息
  - packets.log：符合Prometheus格式的包信息
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
sudo ./netwatch [options] # 运行
sudo make test # 测试
```
## 三、使用方法
`netwatch`通过一系列命令参数来控制其具体行为：

```bash
Usage: netwatch [OPTION...]
Watch tcp/ip in network subsystem

  -a, --all                  set to trace CLOSED connection
  -d, --dport=DPORT          trace this destination port only
  -e, --err                  set to trace TCP error packets
  -i, --http                 set to trace http info
  -r, --retrans              set to trace extra retrans info
  -s, --sport=SPORT          trace this source port only
  -t, --time                 set to trace layer time of each packet
  -x, --extra                set to trace extra conn info
  -?, --help                 Give this help list
      --usage                Give a short usage messages.
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
`netwatch`会将保存在内存中的连接相关信息实时地在`data/connects.log`中更新。默认情况下，为节省资源消耗，`netwatch`会实时删除已CLOSED的TCP连接相关信息，并只会保存每个TCP连接的基本信息。
```
// data/connects.log
connection{pid="44793",sock="0xffff9d1ecb3ba300",src="10.0.2.15:46348",dst="103.235.46.40:80",is_server="0",backlog="-",maxbacklog="-",cwnd="-",ssthresh="-",sndbuf="-",wmem_queued="-",rx_bytes="-",tx_bytes="-",srtt="-",duration="-",total_retrans="-",fast_retrans="-",timeout_retrans="-"} 0
```
#### 3.1.1 保留所有连接信息
对于想要保留所有连接信息的用户，需要指定`-a`参数。
```
sudo ./netwatch -a
```
#### 3.1.2 监控额外连接信息
`netwatch`默认只监控基本连接信息，额外连接信息输出为`-`；对于想要监控额外连接信息的用户，需要指定`-x`参数。
```
sudo ./netwatch -x
```
#### 3.1.3 监控重传信息
`netwatch`监控的额外连接信息并不提供对超时重传次数与快速重传次数的细化；对于想要获取此信息的用户，需要指定`-r`参数。
```
sudo ./netwatch -r
```
### 3.2 监控包信息
`netwatch`会将各个TCP包的相关信息实时地输出在标准输出以及`data/packets.log`中。默认情况下，为节省资源消耗，`netwatch`只会监控各个包的基本信息并输出。
```
sudo ./netwatch
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
`netwatch`提供监控各个数据包在各层的处理时间的支持。为了获得这部分信息，用户需要指定`-t`参数，`netwatch`会输出以`us`为单位的各层处理时间。
```
sudo ./netwatch -t
SOCK                   SEQ        ACK        MAC_TIME   IP_TIME    TCP_TIME   RX    HTTP
0xffff9d1ec43fd780     2018346083 420544002  1          3          9          0     -
0xffff9d1ec43fd780     420544002  2018346160 67         12         494        1     -
0xffff9d1ec43fd780     420545414  2018346160 40         5          258        1     -
```

#### 3.2.2 监控错误数据包
`netwatch`提供对TCP错误的监控支持，用户只需指定`-e`参数，`netwatch`会记录SEQ错误或Checksum错误的TCP包并输出到标准输出以及`data/err.log`中。
```
sudo ./netwatch -e
```

#### 3.2.3 HTTP1/1.1
`netwatch`提供对HTTP1/1.1信息的监控，在指定`-i`参数后，`netwatch`会从携带HTTP请求头的TCP包中将HTTP请求头提取并输出。
```
sudo ./netwatch -i
SOCK                   SEQ        ACK        MAC_TIME   IP_TIME    TCP_TIME   RX    HTTP
0xffff9d1ecb3b9180     3705894662 522176002  -          -          -          0     GET / HTTP/1.1
0xffff9d1ecb3b9180     522176002  3705894739 -          -          -          1     HTTP/1.1 200 OK
```

### 3.3 与Prometheus连接进行可视化
可以注意到，`data`中的所有文件都满足Prometheus要求的时序数据库格式。`netwatch`使用`visual.py`在端口41420暴露`metrics`API为Prometheus提供可视化支持，当Prometheus请求此API时，会获得当前时刻下三个log文件的所有内容。由于三个log文件被eBPF程序实时更新，因此满足时序性。
```
python visual.py
```
## 代码实现细节
- 见`doc/implement.md`