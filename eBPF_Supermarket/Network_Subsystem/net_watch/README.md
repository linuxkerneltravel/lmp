# eBPF-TCP-Watch
## 介绍
本工具通过整合目录`../old`下已有eBPF小工具，在主机空间实现linux网络子系统的：
  - TCP相关的信息监测
  - HTTP1/1.1相关信息检测
## 组织结构
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
## 快速开始
### 安装依赖
- OS: Ubuntu 22.04LTS
```bash
sudo apt update
sudo apt install libbpf-dev clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
git submodule update --init --recursive
```
### 编译运行
```bash
sudo apt insatll bear && bear -- make # 用以生成clang的编译数据库，以供clang-lint使用
make # 如果不需要clang编译数据库，则直接make
sudo ./netwatch [options] # 运行
sudo make test # 测试
```
### 参数
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

## 旧有工具概述
- 下表说明旧有工具的功能简述以及相关监控信息，其中加粗的为tcp_watch监控的关键信息

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

## 实现细节
- 见`doc/implement.md`
