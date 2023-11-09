## BPF数据可视化

​	该项目是eBPF_Visualization项目的一部分，目前是一个命令行工具，实现数据加载到符合Prometheus规范的metrics中，此后，利用prometheus-server方便地对收集地数据进行管理，利用grafana进行数据的可视化。
## 环境要求：
    golang 1.19+
    Docker version 24.0.4+
(docker安装方式参考：https://docs.docker.com/desktop/install/linux-install/)
## 输出的格式要求

第一行输出各项指标的名称，之后每一行输出数据，以空格分隔。

e.g.

```
TIME         READ/s  WRITE/s  FSYNC/s   OPEN/s CREATE/s
14:15:45:      1119       22        0       42        0
14:15:46:       831       28        0      726        0
```

## 使用方式
```bash
make start_service
```
上述命令会自动配置下载docker镜像并启动grafana和prometheus服务。建议一直使用该命令一键式启动所需要的容器。

python封装的bpf程序：
```bash
$ make
$ ./data-visual collect example/vfsstat.py
```

通过ecli工具启动/eBPF_Hub中的bpf程序:
注意，该功能要先安装ecli工具和ecc工具。详见: https://github.com/eunomia-bpf/eunomia-bpf
```bash
$ make
$ ecc ./example/opensnoop/opensnoop.bpf.c ./example/opensnoop/opensnoop.h
$ ./data-visual collect ecli example/opensnoop/package.json
```

程序会自动将bpf程序的输出收集到metrics中。

通过访问http://127.0.0.1:8090/metrics 可实时查看收集到的metrics。

proc_image:
先打开/collector/proc_setting.yaml进行初始化配置，填入需要的信息
```bash
$ make
$ ./data-visual proc_image
```

打开 localhost:8090/metrics 可查看输出的信息。
启动grafana服务，在grafana中安装JSON API,之后选择使用JSON API连接，使用stateTimeline作为展示图，配置方式如下所示：
![8](https://github.com/Gui-Yue/lmp/assets/78520005/60c4f70b-b51f-409a-9715-4fe3c8a0d87d)
![9](https://github.com/Gui-Yue/lmp/assets/78520005/4bf9a907-1a59-4051-a6e4-133d917f96a7)

效果图如下：
![10](https://github.com/Gui-Yue/lmp/assets/78520005/d053b7ef-82a8-4f61-9a68-fd852c987bea)

lock_image:
先打开/collector/tmux_proc_setting.yaml进行初始化适配，填入需要的信息
```bash
$ make
$ ./data-visual tmux
```
打开 localhost:8090/metrics 可查看输出的信息。
启动grafana服务，在grafana中安装JSON API,之后选择使用JSON API连接，使用stateTimeline作为展示图，配置方式如下所示：
![tmux](https://github.com/Gui-Yue/lmp/assets/78520005/02198183-52b7-49f8-a2bb-43b4458e3552)
![tmuxmap](https://github.com/Gui-Yue/lmp/assets/78520005/262b7b04-9009-48f4-86a9-9bf016458eb3)

效果图如下：
![tmuxexhibition](https://github.com/Gui-Yue/lmp/assets/78520005/1e15f09d-ada4-4742-a3ee-e513ede3bb86)

### 使用prometheus-server的docker镜像监控metrics

编辑prom_core/prometheus.yaml中targets参数，使其符合用户ip地址，默认127.0.0.1。

通过访问http://127.0.0.1:9090 可对prometheus-server进行管理。进入Status-Targets,即可看到metrics的状态。
![捕获1](https://github.com/Gui-Yue/lmp/assets/78520005/0ed9e69f-d477-4f7e-91e0-3e9d240f31d3)


### 使用grafana的docker镜像绘图
通过http://127.0.0.1:3000 访问。在grafana中进行可视化设置，选择prometheus服务器，即可实现metrics可视化。效果如下：
![捕获2](https://github.com/Gui-Yue/lmp/assets/78520005/b7bb8668-b3cb-496a-bbfc-ba74ea3ef1b7)

### 通过sqlite3查看收集到的数据
进入/dao目录可以看到data.db数据库文件，通过sqlite3访问查看收集到的数据。

# Grafana配置指南

利用eBPF_prometheus工具，可以搭建其metrics页面和Prometheus服务，之后在grafana中进行简单的配置即可获取直观的可视化数据展示。以下是使用`/lmp/eBPF_Supermarket/Network_Subsystem/net_watch`中的`net_watch`工具作为示例展示如何配置多样化的可视化方案。

## Step1 启动相关服务

在启动监控程序之前，先配置`/lmp/eBPF_Visualization/eBPF_prometheus/prom_core/prometheus.yaml`，scrape_interval是采集密度，即两次采集之间的时间差，targets为metrics服务地址，默认127.0.0.1:8090。

```bash
$ make 
$ make start_service
$ ./data-visual c path/net_watch -t
```

## Step2 配置grafana服务

利用浏览器打开`127.0.0.1:3000`,使用初始密码登录（user:admin   pswd: admin）进入管理界面。

1、建立与Prometheus服务器的连接

![grafana1](https://github.com/Gui-Yue/lmp/assets/78520005/e9b5a550-2f26-4253-a8a4-2fba5e365f9b)


2、选择Prometheus，并按照如图所示进行配置，配置完后点击`Save&test`完成连接的配置

![grafana2](https://github.com/Gui-Yue/lmp/assets/78520005/6a10b977-0aed-4b9b-aac6-305734c6a4a3)


![grafana3](https://github.com/Gui-Yue/lmp/assets/78520005/018aa95a-9ff2-4d6b-9024-495eb906d3b6)

3、可视化配置

按图中所示点击Add，选择Visualization，进入配置界面

![grafana4](https://github.com/Gui-Yue/lmp/assets/78520005/6d182d46-0f1e-47a3-b282-0f9c65a48a57)


在下方query处进行如图所示的配置，点击Run queries即可以可视化的方式监控MAC_TIME字段的输出数据

![grafana5](https://github.com/Gui-Yue/lmp/assets/78520005/91669ba0-b2bf-43e6-9179-1eac68bffa3b)


仪表盘右侧是对图像的一些调整，可以选择想要的可视化效果，也可对图像效果进行调整，例如颜色图形样式等。读者可以自行尝试。

![grafana6](https://github.com/Gui-Yue/lmp/assets/78520005/2d86b7bd-1f86-4e00-97c9-35c5a7ce380d)


配置完成后点击Apply,即可保存可视化方案。

