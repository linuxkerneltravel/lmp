# 概述

本文档用来介绍在云服务器上搭建DDos攻击检测和防御系统框架的流程。

## 环境搭建

### 安装eBPF环境

需要在服务器上安装eBPF的执行环境，在本服务器上已经安装好了eBPF环境。如果需在自己的机器安装eBPF环境，请自行安装官网步骤进行安装。

### 部署一个nginx服务

本服务器首先通过docker快速的部署一个nginx服务，作为服务器待被攻击攻击的对象。

通过以下命令可以快速的获取一个nginx的镜像

```
docker pull nginx
```

通过以下命令可以对nginx镜像进行各种的操作

```
# 启动一个docker服务
docker run -d -p 8080:80 --name=mynginx nginx 	

# 查看系统当前的docker服务信息
docker ps -a 

# 关闭掉一个运行的docker服务
docker rm -f docker_id

# 查看当前系统有哪些docker镜像文件
docker images

# 删除指定的docker镜像文件
docker rmi image_id
```

### 编译代码

本实验的代码是在source/samples/bpf目下编写的，eBPF指标提取模块：zxj_data_kern.c文件、检测算法模块：zxj_test_user.c文件、和xdp防御模块：zxj_defense_kern.c文件。将相应的编译的操作添加到source/samples/bpf/Makefile里面。只需要在source目录执行```make M=sampes/bpf/```即可进行编译。

### XDP程序安装和卸载

通过ip link工具可以实现xdp程序的安装和卸载

```
# 将xdp程序以通用的模式安装到eth0的网卡上。xdp程序支持三种模式：原生模式（即网卡驱动内部实现）、卸载模式（网卡硬件支持）和通用模式
ip link set dev eth0 xdpgeneric obj zxj_xdp2_kern.o sec xdp1

# xdp程序从eth0网卡卸载下来
ip link set dev eth0 xdpgeneric off

# 通过ip link可以直接查看网卡的状态信息，可以通过此命令可以看到xdp程序是否安装成功
ip link
```

### eBPF程序和检测算法的安装

检测算法是在用户态运行的，eBPf程序可以在用户态使用bpf相关的系统调用，将eBPF程序注入到内核中。所以本环境中只需要通过运行检测算法的开始将eBPF程序注入到内核中，就可以同时实现检测算法的安装和eBPF程序注入内核的工作，可以通过运行可执行命令。

```
./zxj_test
```

### 模拟syn flood攻击

需要在另外一个机器上，安装hping3工具。实现对服务器的nginx服务进行攻击。

```
hping3 -S -p 8080 -i u10 1.15.185.16
```

### nginx服务访问方式

可以通过以下两种方式可以访问服务器的ngnix服务，来判断在攻击的情况下，正常用户访问和攻击者访问服务器nginx的情况。

方法一：

curl访问服务器nginx的服务

```
curl -s -w 'Http code: %{http_code}\nTotal time:%{time_total}s\n' http://1.15.185.16:8080
```

方法二：

web浏览器http协议请求方式访问

```
http://1.15.185.16:8080
```

### 云服务器数据收发情况产看

通过```sar -n```命令可以查看系统网卡的收发包情况，来判断服务器是否部署检测和防御系统的收发包情况，来验证框架是否有用。

```
sar -n DEV 1
```

