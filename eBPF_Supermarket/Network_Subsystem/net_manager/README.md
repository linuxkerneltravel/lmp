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
router:对内核中网络包进行加速路由。
xacl_ip:通过IP地址对数据包进行拦截
xacl_mac:通过mac地址对数据包进行拦截
sockmap:实现同主机内内核中多个进程之间网络包发送加速优化。
```
