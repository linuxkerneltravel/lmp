# eBPF-TCP-Watch
## 介绍
基于目前已有eBPF小工具，以及linux网络协议栈相关探测点，该项目在主机空间实现以下功能：
- 记录TCP连接层面相关信息
- 记录TCP包层面相关信息
- 从TCP包中提取HTTP1/1.1相关信息
- 暴露HTTP接口提供给Prometheus以进行可视化
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
  -s, --sport=SPORT          trace this source port only
  -?, --help                 Give this help list
      --usage                Give a short usage message
```