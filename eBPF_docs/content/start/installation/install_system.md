---
title: 基本环境安装（非Docker环境）
description : "介绍 LMP 运行的基本环境安装。"
weight: 10
---

### 〇、所需环境一览

- Ubuntu 20.04 ，内核版本5.4.0-90-generic（非必须，但本文基于此版本配置安装）
- BCC
- Golang（>=1.12）
- MySQL （5.7测试通过）
- InfluxDB（1.8测试通过）

### 一、BCC安装与配置

官方安装说明文档(github)：https://github.com/iovisor/bcc/blob/master/INSTALL.md

#### 1.安装依赖
>- LLVM 3.7.1 or newer, compiled with BPF support (default=on)
>- Clang, built from the same tree as LLVM
>- cmake (>=3.1), gcc (>=4.7), flex, bison
>- LuaJIT, if you want Lua support

一键安装以上依赖：
```
sudo apt install -y bison build-essential cmake flex git libedit-dev \
  libllvm7 llvm-7-dev libclang-7-dev python zlib1g-dev libelf-dev libfl-dev
```

#### 2.下载并安装bcc

##### 方法一（使用源码编译安装）

下载bcc的release版本（如果第一个过慢可以试试第二个gitee版的）：

```
wget https://github.com/iovisor/bcc/releases/download/v0.23.0/bcc-src-with-submodule.tar.gz
```
（其他版本：https://github.com/iovisor/bcc/releases）

解压：
```
tar -zxvf bcc-src-with-submodule.tar.gz
```

进入bcc所在目录，执行下列命令：

```
mkdir build;cd build
cmake ..
make;sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
make;sudo make install
```

##### 方法二（使用apt安装）

```
sudo apt-get install bpfcc-tools
```

#### 3.测试

在`sudo python3`下运行以下程序：

```
from bcc import BPF
BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()
```

![image-20220114224845536](../images/202201142248579.png)

### 二、Golang安装与配置

#### 1.安装

```
wget https://golang.google.cn/dl/go1.16.13.linux-amd64.tar.gz
tar -zxvf go1.16.13.linux-amd64.tar.gz
sudo mv go /usr/local #将解压出的go目录移动到/usr/local（可根据自己实际情况修改）
```

#### 2.配置环境变量

修改文件 `/etc/profile` 

```
sudo vim /etc/profile
```

在文件末尾添加以下内容：（以go所在路径为`/usr/local/go`为例，需要根据go的实际路径修改）

```
export GOROOT=/usr/local/go #go所在路径
export GOPATH=$GOROOT/goProject #工作目录
export GOBIN=$GOPATH/bin
export PATH=$PATH:$GOROOT/bin
export PATH=$PATH:$GOPATH/bin
```

使修改生效：

```
source /etc/profile
```

#### 3.测试

```
go version
```

<img src="../images/202201142245428.png" alt="image-20220114224539249" style="zoom:50%;" />

### 三、MySQL安装与配置

#### 1.安装
先安装libinfo5
```
sudo apt-get install libtinfo5
```
由于Ubuntu20.04的apt源无法安装mysql5.7，需要切换apt源
```
#备份原有的sources.list并删除
sudo cp /etc/apt/sources.list /etc/apt/sources.list.old
sudo rm /etc/apt/sources.list
#创建新的sources.list
sudo vim /etc/apt/sources.list
```
复制以下内容到sources.list
```
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial main restricted universe multiverse
deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse
deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-updates main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse
deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-backports main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security main restricted universe multiverse
deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ xenial-security main restricted universe multiverse
```
按顺序分别安装：
```
sudo apt-get install mysql-client-core-5.7
sudo apt-get install mysql-client-5.7
sudo apt-get install mysql-server-5.7
```
最后需要配置mysql密码（lmp配置文件config.yaml的默认密码为123）
![image-20220116155303403](../images/202201161553441.png)
再将apt源切换回去

```
sudo cp /etc/apt/sources.list.old /etc/apt/sources.list
sudo apt-get update
```

#### 2.测试

```
mysql -u root -p
```

提示Enter password，输入配置的密码

![image-20220116170614026](../images/202201161706077.png)

### 四、InfluxDB安装与配置

#### 1.安装

```
wget -qO- https://repos.influxdata.com/influxdb.key | sudo apt-key add -
source /etc/lsb-release
echo "deb https://repos.influxdata.com/${DISTRIB_ID,,} ${DISTRIB_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/influxdb.list
sudo apt update
sudo apt install influxdb
```

#### 2.配置

```
#启动系统服务
sudo systemctl enable --now influxdb
```

#### 3.测试

```
influx
```

<img src="../images/202201201719165.png" alt="image-20220120171928444" style="zoom:67%;" />
