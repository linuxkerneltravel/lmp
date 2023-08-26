# eBPF-TCP-Watch
## 介绍
基于目前已有eBPF小工具，以及linux网络协议栈相关探测点，该项目在主机空间实现以下功能：
### 已完成
- 搭建基础开发框架和自动编译管道。
- 设计并实现TCP连接信息的记录
- 设计并实现各个TCP连接发送与接收包信息的记录
- 设计并实现TCP错误包信息的记录
- 实现从TCP包中抽取HTTP信息并记录
- 增加运行时参数以提升可用性，避免不必要的内核开销
### TODO
## 组织结构
- tcpwatch.bpf.c：在各个内核探针点对TCP包信息、TCP连接信息以及各个包的HTTP1/1.1信息进行记录
- tcpwatch.c: 对bpf.c文件中记录的信息进行输出
- tcpwatch.h: 定义内核态与用户态程序共用的结构体
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
make
sudo ./tcpwatch
```
### 参数
```bash
Usage: tcpwatch [OPTION...]
Watch tcp/ip in network subsystem

  -a, --all                  set to trace CLOSED connection
  -d, --dport=DPORT          trace this destination port only
  -e, --err                  set to trace TCP error packets
  -i, --http                 set to trace http info
  -r, --extra                set to trace extra conn info
  -s, --sport=SPORT          trace this source port only
  -t, --time                 set to trace layer time of each packet
  -?, --help                 Give this help list
      --usage                Give a short usage message
```
- 参数`-d`,`-s`用于指定监控某个源端口/目的端口
- 指定参数`-a`会保留已CLOSED的TCP连接信息
- 指定`-e`参数会记录SEQ错误或Checksum错误的TCP包
- 默认情况下，监控以下连接信息与包信息：
    - TCP连接pid
    - TCP连接\[源地址:端口,目的地址:端口\]
    - TCP连接sock地址
    - TCP包sock地址（用于明确TCP连接）
    - TCP包ack
    - TCP包seq
- 指定`-t`参数会监控各个包在每一层的处理时间，单位us
- 指定`-r`参数会监控以下额外连接信息：
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