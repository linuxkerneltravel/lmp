# Linux microscope

## 项目目标

1. 帮助运维人员更全面地了解系统实时运行状态
2. 希望通过BPF技术来探测系统性能数据
3. 能够通过web形式展示性能数据



## startup

TODO...

## 项目架构

![](./static/imgs/arch.png)

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

## 本地测试

### 编译
```sh
$ docker pull prom/prometheus
$ docker pull grafana/grafana
$ git clone https://github.com/linuxkerneltravel/lmp
$ cd lmp
$ make
$ make install

  这里需要将/opt/prometheus/prometheus.yml中xxx替换为本机的IP地址

$ docker run  -d \
$   -p 9090:9090 \
$   -v /opt/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml  \
$   prom/prometheus

$ docker run -d \
$   -p 3000:3000 \
$   --name=grafana \
$   -v /opt/grafana-storage:/var/lib/grafana \
$   grafana/grafana

$ ./cmd/main
```

### 打开浏览器进行本地观测
http://localhost:8080/
登录grafana之后，导入/opt/grafana下的dashboard.json文件即可查看。

### 卸载
```sh
$ make clean
```

## 感谢以下开源项目的支持

- [Gin] - [https://gin-gonic.com/](https://gin-gonic.com/)
- [bcc] - [https://github.com/iovisor/bcc](https://github.com/iovisor/bcc)