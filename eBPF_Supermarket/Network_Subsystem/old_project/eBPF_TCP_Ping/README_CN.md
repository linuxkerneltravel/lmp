[English](./README.md)

# eBPF-TCP-Ping

## 介绍

基于 ebpf 的 tcp ping 命令行工具，通过 kprobe 来在内核态而非用户态计算 RTT。并且可使用 XDP 做回包的加速

- tcp_ping.go: TCP ping 命令行工具，它会发送 TCP SYN 包给指定的服务器，并且使用 eBPF 去 hook 内核 TCP 状态转换的函数来计算 RTT

- xdp_ping.c: XDP 程序, 将会被加载到内核或网卡中。在 TCP SYN 包进入内核协议栈之前，它会原地修改数据包为 RST 后原路返回


## 快速开始

### 加载 XDP 程序到 NIC

**XDP 的加载是可选的，仅仅只是用于加速回包。可以选择使用 kernel 自带的回包而不是 XDP**

请检查 Makefile 中的 NIC 变量
```Makefile
NIC   ?= eth0
```

安装和卸载 XDP 程序
```
make
sudo make install
sudo make uninstall
```

### ping 其他服务器

帮助命令

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

该工具探测的是 65532 端口，所以务必注意被 ping 的服务器需要开放 65532 端口
