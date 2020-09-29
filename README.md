![](./static/imgs/LMP-logo.png)
# Linux microscope

LMP is a web tool for real-time display of Linux system performance data based on BCC (BPF Compiler Collection), which uses BPF (Berkeley Packet Filter), also known as eBPF. Currently, LMP is tested on ubuntu18.04 and the kernel version is 4.15.0.

## Project architecture
![](./static/imgs/LMP-arch4.png)

## Interface screenshot

![homepage2](./static/imgs/homepage2.png)

![homepage](./static/imgs/grafana.png)

![homepage](./static/imgs/data.png)


## Project structure overview  

<details>
<summary>Expand to view</summary>
<pre><code>.
.
├── LICENSE
├── README.md
├── bcctest            Hold all test codes, including bcc、influxdb, etc
├── cmd                Store LMP pid number after startup
├── config.yaml        Project profile
├── controllers        Controller layer code stored in CLD layers
├── dao                Dao layer code stored in CLD layers
├── logger             Zap Log Library Initialization Related Code
├── logic              Logic layer code stored in CLD layers
├── main.go
├── makefile
├── middlewares        Holds middleware, such as JWT, used in the project
├── models             Data structure, such as a user、BpfScan, used in a storage project
├── pkg                A third-party library, such as JWT、snowflake, used in a project
├── plugins            Storage bcc plugins
├── routes             Store initialization routing code
├── settings           Hold viper Initialize related code
├── static             Hold static HTML files, pictures, etc
├── test               Store influxdb initial configuration, files, etc
└── vendor             Storage of project dependencies
</code></pre>
</details>

##  install lmp

###  Ubuntu-source

#### Build lmp from source，The basic environment required is as follows：

- golang
- docker

###  Install dependent docker image

```
# For prometheus 
 docker pull prom/prometheus
# For grafana
 docker pull grafana/grafana
# For MySql
 docker pull mysql
```

### Compile and install

```
 git clone https://github.com/linuxkerneltravel/lmp
 cd lmp
 make
 make install
```

##  Single machine node, Run locally

```
# Modify configuration file
 vim lmp/config.yaml

#run grafana
 docker run -d \
   -p 3000:3000 \
   --name=grafana \
   -v /opt/grafana-storage:/var/lib/grafana \
   grafana/grafana
   
#run influxdb
    docker run -d \
    -p 8083:8083 \
    -p 8086:8086 \
    --name influxdb \
    -v ${YOUR_PATH}/lmp/test/influxdb_config/default.conf:/etc/influxdb/influxdb.conf \
    -v ${YOUR_PATH}/lmp/test/influxdb_config/data:/var/lib/influxdb/data \
    -v ${YOUR_PATH}/lmp/test/influxdb_config/meta:/var/lib/influxdb/meta \
    -v ${YOUR_PATH}/lmp/test/influxdb_config/wal:/var/lib/influxdb/wal influxdb

#run lmp
 cd lmp/
 ./lmp
```

### observation

http://localhost:8080/  After logging in to grafana, view it.

### Uninstall

```
make clean
```

## Thanks for the support of the following open source projects

- [Gin] - [https://gin-gonic.com/](https://gin-gonic.com/)
- [bcc] - [https://github.com/iovisor/bcc](https://github.com/iovisor/bcc)

# ZH

![](./static/imgs/LMP-logo.png)
# Linux microscope

LMP是一个基于BCC(BPF Compiler Collection)的Linux系统性能数据实时展示的web工具，它使用BPF(Berkeley Packet Filters)，也叫eBPF，目前LMP在ubuntu18.04上测试通过，内核版本4.15.0。

## 项目架构

![](./static/imgs/LMP-arch4.png)

## 界面截图

![homepage2](./static/imgs/homepage2.png)

![homepage](./static/imgs/grafana.png)

![homepage](./static/imgs/data.png)

## 项目结构概览

<details> 
<summary>展开查看</summary>
<pre><code>
.
├── LICENSE
├── README.md
├── bcctest            存放所有的测试代码，包括bcc、influxdb等
├── cmd                存放LMP启动之后的pid号
├── config.yaml        项目配置文件
├── controllers        存放CLD分层中的controller层代码
├── dao                存放CLD分层中的dao层代码
├── logger             存放zap日志库初始化相关代码
├── logic              存放CLD分层中的logic层代码
├── main.go
├── makefile
├── middlewares        存放项目中使用到的中间件，例如JWT
├── models             存放项目中使用到的数据结构，例如user、BpfScan等
├── pkg                存放项目中使用的第三方库，例如JWT、snowflake等
├── plugins            存放bcc插件
├── routes             存放初始化路由相关代码
├── settings           存放viper初始化相关代码
├── static             存放静态HTML文件、图片等
├── test               存放influxdb初始配置、文件等
└── vendor             存放项目依赖库    
</code></pre>
</details>

##  安装lmp

###  Ubuntu-source

#### 从源码构建lmp，需要的基本环境：

- golang
- docker
- bcc环境

###  安装依赖docker镜像

```
# For prometheus 
 docker pull prom/prometheus
# For grafana
 docker pull grafana/grafana
# For MySql
 docker pull mysql
```

### 编译并安装

```
 git clone https://github.com/linuxkerneltravel/lmp
 cd lmp
 make
 make install
```

## 单机节点，本地运行

```
# 修改配置文件
 vim lmp/config.yaml

#run grafana
 docker run -d \
   -p 3000:3000 \
   --name=grafana \
   -v /opt/grafana-storage:/var/lib/grafana \
   grafana/grafana

#run influxdb
    docker run -d \
    -p 8083:8083 \
    -p 8086:8086 \
    --name influxdb \
    -v ${YOUR_PATH}/lmp/test/influxdb_config/default.conf:/etc/influxdb/influxdb.conf \
    -v ${YOUR_PATH}/lmp/test/influxdb_config/data:/var/lib/influxdb/data \
    -v ${YOUR_PATH}/lmp/test/influxdb_config/meta:/var/lib/influxdb/meta \
    -v ${YOUR_PATH}/lmp/test/influxdb_config/wal:/var/lib/influxdb/wal influxdb


#run lmp
 cd lmp/
 ./lmp
```

### 进行观测

http://localhost:8080/ 登录grafana之后，即可观测。

### 卸载

```
make clean
```

## 感谢以下开源项目的支持

- [Gin] - [https://gin-gonic.com/](https://gin-gonic.com/)
- [bcc] - [https://github.com/iovisor/bcc](https://github.com/iovisor/bcc)



