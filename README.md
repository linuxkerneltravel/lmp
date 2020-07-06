# Linux microscope

LMP是一个基于BCC(BPF Compiler Collection)的Linux系统性能数据实时展示的web工具，它使用BPF(Berkeley Packet Filters)，也叫eBPF，目前LMP在ubuntu18.04上测试通过，内核版本4.15.0。

## startup

TODO...

## 项目架构

![](./static/imgs/LMP-arch3.png)

## 界面截图

<details>
<summary>展开查看</summary>
<pre><code>
<img src="./static/imgs/homepage.png" width="2880" height="450" /><br/><br/>
</code></pre>
</details>

## 项目结构概览

<details>
<summary>展开查看</summary>
<pre><code>.
├── README.md
├── api   协议文件、前端交互的接口文件等, 本项目的路由设置与路由函数
├── cmd   main函数文件目录
├── config   配置文件
├── deployments   后端下发的一些配置文件与模板
├── docs   本项目设计文档，项目经历记录文档等
├── go.mod
├── go.sum
├── internal   本项目封装的代码，其中包括BPF代码等
├── pkg   通用的可以被其他项目所使用的一些代码
├── static   项目用到的一些静态页面，包括前端静态展示页、图片等
├── test   测试目录，包括功能测试，性能测试等
└── vendor   本项目依赖的其它第三方库
</code></pre>
</details>

##  安装lmp

###  Ubuntu-source

#### 从源码构建lmp，需要的基本环境：

- golang
- docker

###  安装依赖docker镜像

```
# For prometheus 
 docker pull prom/prometheus
# For grafana
 docker pull grafana/grafana
```

### 编译并安装

```
 git clone https://github.com/linuxkerneltravel/lmp
 cd lmp
 make
 make install
```

## 本地运行

```
# 修改配置文件
 将/opt/prometheus/prometheus.yml中xxx替换为本机的IP地址
#run prometheus
 docker run  -d \
   -p 9090:9090 \
   -v /opt/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml  \
   prom/prometheus

#run grafana
 docker run -d \
   -p 3000:3000 \
   --name=grafana \
   -v /opt/grafana-storage:/var/lib/grafana \
   grafana/grafana

#run lmp
 ./cmd/main
```

### 进行观测

http://localhost:8080/ 登录grafana之后，导入/opt/grafana下的json文件即可查看。

### 卸载

```
make clean
```

## 感谢以下开源项目的支持

- [Gin] - [https://gin-gonic.com/](https://gin-gonic.com/)
- [bcc] - [https://github.com/iovisor/bcc](https://github.com/iovisor/bcc)



# English

# Linux microscope

LMP is a web tool for real-time display of Linux system performance data based on BCC (BPF Compiler Collection), which uses BPF (Berkeley Packet Filter), also known as eBPF. Currently, LMP is tested on ubuntu18.04 and the kernel version is 4.15.0.

## startup

TODO...

## Project architecture
![](./static/imgs/LMP-arch3.png)

## Interface screenshot

<details>
<summary>Expand to view</summary>
<pre><code>
<img src="./static/imgs/homepage.png" width="2880" height="450" /><br/><br/>
</code></pre>
</details>


## Project structure overview  

<details>
<summary>Expand to view</summary>
<pre><code>.
├── README.md
├── api   Protocol files, interface files for front-end interaction, etc., the routing settings and routing functions of this project
├── cmd   File of Main()
├── config   Configuration
├── deployments   Some configuration and templates issued by the backend
├── docs   Design document, record document, etc.
├── go.mod
├── go.sum
├── internal   The code encapsulated in this project, including BPF code, etc.
├── pkg   Common code that can be used by other projects
├── static   Some static pages used in the project, including front-end static display pages, pictures, etc.
├── test  Test catalog, including functional test, performance test, etc.
└── vendor   Other third-party libraries that this project depends on
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
```

### Compile and install

```
 git clone https://github.com/linuxkerneltravel/lmp
 cd lmp
 make
 make install
```

## Run locally

```
# Modify configuration file
 Replace xxx in /opt/prometheus/prometheus.yml with the IP address of the machine
#run prometheus
 docker run  -d \
   -p 9090:9090 \
   -v /opt/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml  \
   prom/prometheus

#run grafana
 docker run -d \
   -p 3000:3000 \
   --name=grafana \
   -v /opt/grafana-storage:/var/lib/grafana \
   grafana/grafana

#run lmp
 ./cmd/main
```

### observation

http://localhost:8080/  After logging in to grafana, import the json file under /opt/grafana to view it.

### Uninstall

```
make clean
```

## Thanks for the support of the following open source projects

- [Gin] - [https://gin-gonic.com/](https://gin-gonic.com/)
- [bcc] - [https://github.com/iovisor/bcc](https://github.com/iovisor/bcc)
