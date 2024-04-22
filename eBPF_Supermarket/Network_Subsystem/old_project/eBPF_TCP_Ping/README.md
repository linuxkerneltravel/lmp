[中文](./README_CN.md)

# eBPF-TCP-Ping

## Introduction

TCP ping command tool based on ebpf, using kprobe to calculate RTT in the kernel space rather than user space. In addition, we can speed up the packet return through XDP.

- tcp_ping.go: TCP ping command tool, it can send a TCP SYN packet to other server, and use the eBPF to hook kernel tcp status function to calculate RTT.

- xdp_ping.c: XDP program, it will be loaded to kernel or NIC. Before SYN packet enter the kernel protocol stack, it can rewrite the packet into RST and return the original way.

## Quick Start
### load XDP program to NIC

**The loading of XDP is optional and is only used to speed up the packet return. You can choose to use the return packet that comes with the kernel instead of XDP.**

Please check your NIC in Makefile

```Makefile
NIC   ?= eth0
```

install or uninstall XDP program
```
make
sudo make install
sudo make uninstall
```

### ping other server

help

```
➜  sudo go run tcp_ping.go -h
tcp_ping version: 0.0.1
Usage: tcp_ping 172.217.194.106 [-d 500] [-c 100] [-s]

Options:
  -c Number
    	Number connections to keep ping (default 1)
  -d duration
    	Ping duration ms (default 1000)
  -h	Show help
  -s	Do not show information of each ping
```

The tool detects port 65532, noted that port 65532 of other server needs to be opened
