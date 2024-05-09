# eBPF网络包追踪技术赛 —— Netwacher

## 工具介绍

netwatcher作为一款基于eBPF的网络检测工具，其设计初衷是帮助用户能够在主机环境中，轻松快捷地获取到 Linux 网络协议栈的详细信息，通过高效的数据收集和精准的监控能力，深入了解网络行为，确保网络安全和性能的优化，其应用范围涉及较广。
netwatcher能够追踪TCP、UDP、ICMP协议数据包从应用程序发出开始，经过内核协议栈到驱动、最终发出过程（发包路径）的时延数据和流量信息，以及数据包从驱动到内核协议栈到用户态程序的过程（收包路径）中的时延数据。对获取到的时延数据采用算法进行阈值比较捕获异常时延数据并给予警告信息。同时监测TCP连接的状态信息（seq、ack、连接状态、重传信息、错误信息、rwnd、cwnd、sndbuf等关键指标），并且可以监控丢包事件（包括skb_drop_reason中定义的77种原因）。
其有助于及时解决各种网络问题，提高系统稳定性和服务可靠性。无论是云计算所需要的确保其基础设施的稳定性和安全性，还是金融机构需要保障交易的及时性和安全性，亦或是电子商务企业追求用户体验和网站性能的优化，netwatcher都提供了强大的网络监测和优化能力，满足不同行业的需求，助力企业顺利应对数字化时代的挑战。

## 使用介绍

```
Usage:  [OPTION...]
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
      --usage                Give a short usage message
```
## Quick Start

- 安装依赖（Ubuntu为例）

```
sudo apt install clang llvm libelf-dev libpcap-dev build-essential 
```

- 拉取项目

```
git clone https://atomgit.com/fusionos/0000004.git
```

- 编译

```
make -jN
```

- 测试运行

```
sudo ./netwacher
```

## 目录结构

```
.
├── common.bpf.h 定义了一些数据包头部之间转换的辅助函数、宏、BPF映射、以及内核中使用到的结构体。
├── data 文件夹存放打印的日志信息，connect.log、err.log、packets.log、udp.log。
├── docs 比赛相关文档与演示视频
├── drop.bpf.h 数据包丢弃原因的具体处理逻辑。
├── dropreason.h 字符串数组描述数据包可能丢弃的各种原因。
├── icmp.bpf.h  icmp数据包收发包时延具体实现细节。
├── lib 基于的libbpf库、bpftool以及vmlinux
├── LICENSE.txt
├── Makefile
├── netfilter.bpf.h 封装了处理网络过滤器netfilter时延的具体逻辑，submit_nf_time函数用于将时延信息提交到用户态，而store_nf_time函数则用于存储经过每个HOOK点的时延。
├── netwatcher.bpf.c 定义kprobe、kretprobe、tracepoint挂载的内核函数。
├── netwatcher.c netwatcher主程序的入口函数，定义了命令行参数、打印函数。
├── netwatcher.h netwatcher中的一些结构体、常量定义
├── packet.bpf.h 封装了一系列与网络数据包的处理、时间戳的记录、数据包信息的提取等相关函数。
├── README.md
├── tcp.bpf.h 网络数据包处理以及连接状态等信息具体实现细节。
└── udp.bpf.h udp数据包收发过程时延、流量的具体处理逻辑。
```

## 设计思路与性能测试

测试环境为：Ubuntu 23.10 (kernel 6.5)

详细可见作品申报书：

Word 版本：`docs/eBPF网络包追踪应用技术赛_作品申报书.docx`

PDF 版本：`docs/eBPF网络包追踪应用技术赛_作品申报书.pdf`

## 演示视频

`docs/eBPF网络包追踪应用技术赛_演示视频.mp4`