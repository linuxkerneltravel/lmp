# net_manager项目

## 一、项目简介

`net_manager` 是一个基于 eBPF 技术的项目，旨在提高内核对数据包的处理能力。该项目基于 eBPF 技术，通过在宿主机中执行eBPF程序，能够在数据包到达主机的早期对数据包进行处理，实现高性能的网络数据包拦截能力。对内核中网络包进行加速路由，实现同主机内内核中多个进程之间网络包发送加速优化。

## 二、功能介绍

`net_manager`是一款基于eBPF的数据包处理工具工具，旨在提高内核对数据包的处理能力。

目前，其实现的功能主要包括：

- 实现高性能的网络数据包拦截能力
- 网络包加速路由
- 同主机内内核中多个进程之间网络包发送加速优化

## 三、使用方法

> 环境：
>
> Kernel: Linux6.2  
>
> OS: Ubuntu 23.04
>

**安装依赖：**

```
sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386
sudo apt install linux-headers-$(uname -r)
```


**编译运行：**

```
sudo ./configure
sudo make
```

**功能介绍：**

`net_manager`通过一系列命令参数来控制其具体行为：

```
防火墙：建议加载到本地链路 ens33 上
sudo ./xdp_loader -d ens33 --progname xdp_entry_ipv4 -S
sudo ./xdp_loader -d ens33 --progname xdp_entry_mac -S

路由转发：建议加载到本地链路 ens33 上
sudo ./xdp_loader -d ens33 --progname xdp_entry_router -S
tcpdump抓包时会进入混乱模式，观察时建议指定mac地址
sudo tcpdump ether src MAC and ether dst MAC

会话保持：建议加载到本地链路 lo 上
sudo ./xdp_loader -d lo --progname xdp_entry_state -S
客户端：nc localhost 1234
服务端：sudo nc -l 1234

规则加载方式：
sudo ./xacladm ip ens33 ./conf.d/black_ipv4.conf
sudo ./xacladm mac ens33 ./conf.d/mac_load.conf
sudo ./xacladm router ens33 ./conf.d/router_load.conf

卸载方式：
可以将多个XDP程序加载到同一张网卡上，每个程序都会在数据包到达时被调用。
当数据包到达时，系统会按照XDP程序加载的顺序执行这些程序。这意味着如果一个程序决定丢弃数据包，那么后续的程序将不会被执行。
因此，建议每次加载一个xdp程序，在加载下一个程序之前进行卸载。
sudo xdp-loader unload ens33 --all
sudo xdp-loader unload lo --all
```
