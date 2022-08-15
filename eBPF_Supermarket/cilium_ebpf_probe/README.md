# 基于 eBPF 的云原生场景下 Pod 性能监测

---
# **如何运行**

**环境情况**

| Require | Version          |
| ------- |:-----------------|
| Linux   | 5.17.5           |
| CentOS  | 7.9.2009 (Core)  |
| GCC     | 11.2.1           |
| LLVM    | 11.0.0           |
| GoLang  | 1.18 Linux/amd64 |

将本项目从Git仓库Clone下后，首先在cilium_ebpf_probe/k8s_yaml文件下通过kubectl apply命令在namespace“wyw”中创建grpc_server和http_server pod，等待pod变更为Running状态。namespace可在yaml文件中进行自定义设计。

```bash
[root@k8s-master k8s_yaml]# kubectl get pods -n wyw
NAME         READY   STATUS    RESTARTS   AGE
grpcserver   1/1     Running   0          3m2s
httpserver   1/1     Running   0          3h46m
```

在cilium_ebpf_probe目录下直接运行go run  main.go即可，go会自动下载所需依赖。

当出现如下报错时，显示gobpf和bcc版本不匹配所导致，在go.mod中修改gobpf@v0.0.0-20210109143822-fb892541d416为gobpf@v0.1.0或gobpf@v0.2.0至能运行即可。

```bash
/root/go/pkg/mod/github.com/iovisor/gobpf@v0.0.0-20210109143822-fb892541d416/bcc/module.go:230:132: not enough arguments in call to (_C2func_bcc_func_load)
        have (unsafe.Pointer, _Ctype_int, *_Ctype_char, *_Ctype_struct_bpf_insn, _Ctype_int, *_Ctype_char, _Ctype_uint, _Ctype_int, *_Ctype_char, _Ctype_uint, nil)
        want (unsafe.Pointer, _Ctype_int, *_Ctype_char, *_Ctype_struct_bpf_insn, _Ctype_int, *_Ctype_char, _Ctype_uint, _Ctype_int, *_Ctype_char, _Ctype_uint, *_Ctype_char, _Ctype_int)

```
为了进行可视化展示，需要通过以下流程对prometheus组件进行部署。

**1.Docker启动普罗米修斯**

```bash
$ docker run --name prometheus -v /etc/localtime:/etc/localtime -d -p 9090:9090 prom/prometheus:latest 
```

这里默认 Prometheus 开放 9090 端口，我们使用最新版官方镜像，当前最新版本为 v2.11.1，启动完成后，浏览器访问 http://<IP>:9090 即可看到默认 UI 页面。

**2.Docker启动pushgateway**

```bash
$ docker run --name pushgateway -v /etc/localtime:/etc/localtime -d -p 9091:9091 prom/pushgateway 
```

**3.将pushgateway和prometheus进行关联**

Prometheus 默认配置文件 prometheus.yml 在[容器](https://cloud.tencent.com/product/tke?from=10680)内路径为 /etc/prometheus/prometheus.yml添加prometheus.yml配置如下

```bash
...
- job_name: 'pushgateway'
    honor_labels: true
    static_configs:
      - targets: ['10.10.103.122:9091'] #pushgateway的端口
        labels:
          instance: pushgateway
```

完成后重启prometheus`docker restart prometheus`

**4.Docker启动Grafana**

```bash
$ docker run -d -p 3000:3000 --name grafana -v /etc/localtime:/etc/localtime grafana/grafana-enterprise:8.1.3
```

接下来打开http://<IP>:3000即可查看Grafana界面。并将对应的传送API接口修改，即可成功运行本探针程序。

---

# 1.项目背景

​	Kubernetes 是云原生领域的容器编排系统，内部原理复杂但对外界使用者透明。其中pod是kubernetes 项目的原子调度单位，因此，容器级别的数据监测是 Kubernetes 集群中十分重要的一环。当容器出现资源占用过多、性能下降等问题时，目前现有的APM工具能得到的Metric数据，大多为统计型数据，Pod 对应的进程网络传输报文数、网络状态等总体情况，而不能定位到问题出现在哪个阶段，并且如Promethues和Zabbix等工具主要数据来源是通过/proc进行挖掘，存在检测效率低、性能差等问题。而一些特有的内核函数执行结果与实践，内容珍贵，例如`do fork`内核函数返回报错，则代表内核可用PID耗尽，`count_mounts`内核函数返回文件数量报错则代表加载数量超过内核限制，值得挖掘。

​	例如，当前的众多云业务架构因为分工问题，容易出现服务数量多，服务关系复杂的现象，出现无法确定特定服务的下游依赖服务是否正常、无法回答应用之间的连通性是否正确等问题。因此，需要以容器为核心，采集关联的 Kubernetes 可观测数据，与此同时，向下采集容器相关进程的系统和网络可观测数据，向上采集容器相关应用的性能数据，通过关联关系将其串联起来，完成端到端可观测数据的覆盖，在过程中能够追寻trace。

# 2.解决方案

1. 提取系统调用中网络栈相关的黄金指标（latency、traffic、errors、saturation），如流量、重传、RTT、丢包率，以及错误数、慢调用数、请求数、半连接数量、全连接数量等内容；
1. 在必要的情况下，提取网络栈中进程的调用函数，确定各部分的资源损耗和工作时延。
1. 在用户层，将探针结果与应用态信息匹配，包括Docker、Pod等内容。

# 3.方法设计

## 3.1内核网络跟踪指标

​	数据包在内核中使用`sk_buff`结构体来传递，网络套接字是用`sock`结构体定义的，该结构体在各网络协议结构体的开头部分存放，如`tcp_sock`结构体，在`tcp_prot`、`udp_prot`部分挂载了网络协议，需要保证查看的`socket`结构体的状态处于full套接字状态，才能得到有效数据。

### 3.1.1可供追踪的基础指标

1. 可从各个不同的角度测量网络延迟：DNS延迟、连接延迟、首字节延迟、软件栈各层之间的延迟等，并在**有负载的情况和空闲网格中**分别测量这些延迟，以进行比较;
2. TCP连接创建的相关事件，跟踪`sock:inet_sock_set_state`跟踪点等，检查状态从`TCP_CLOSE`到`TCP_SYN_SENT`状态的变化，跟踪新TCP连接的建立和时长；
3. TCP的被动连接连接，跟踪`inet_csk_accept`内核函数，检测TCP监听溢出情况;
4. TCP的连接时长，根据`sock:inet_sock_set_state`，当状态变为`TCP_CLOSE`的时候就可以进行信息的抓取；
5. 跟踪TCP重传或者其他的TCP事件，如`tcp_drop`、`skb:kfree_skb`等跟踪点；

### 3.1.2其他信息

1. 采样内核调用栈信息来分析网络相关代码路径所占的时间比例；
2. 当某些情况异常时，可以对skb结构体的生命周期时长，进行短期监控，显示内核网络栈中是否存在延迟情况以及锁等待的情况；对网络设备的发送延迟进行统计，测量网络包发送到设备队列`net:net_dev_start_xmit`和设备发送完成`skb:consume_skb`跟踪点之间的时间差
3. 使用高频CPU性能分析抓取内核调用栈信息，以量化CPU资源在网络协议和驱动程序之间的使用情况，如off-cpu情况、cgroup限制的影响、页错误等情况。

### 3.1.3HTTP请求采集

​	在TCP的基础上，对HTTP请求进行采集。主要分为三步：数据采集、请求/响应关联和请求/响应解析。

#### （1）数据采集

​	HTTP服务当接收到请求时会有accept/read/write/close等函数执行，这些函数最终执行内核的系统调用，例如一次请求会通过read接收HTTP请求，并通过write进行日志输出以及返回HTTP结果，因此分别通过`ssize _t read(int fd,void* buf,ssize_t count)`和`ssize _t write(int fd,void* buf,ssize_t count)`的追踪可以转换为event。

#### （2）请求/相映关联

​	常规的TCP请求都会用同一个fd进行通信，只需根据进程号和fd能关联同一个请求和响应。在同一个socket fd上的read系统调用和wrtie系统调用即可得到应用在处理该socket上请求耗时，并将该次请求与返回封装成排障trace。通过耗时、返回码等业务层语义能够确定每次eBPF排障trace是否异常：

#### （3）请求/响应解析

​	通过**协议识别**和**协议解析**完成。

​	在协议识别部分，可以通过特征或关键字快速匹配协议，对于HTTP请求来说，通过HTTP版本号(HTTP/1.0或HTTP/1.1)可以快速识别协议。

​	在协议解析部分，是为了产生指标用于后续分析，在解析过程中需根据协议自身的格式进行解析。

## 3.2 应用层关联

​	容器是操作系统级别的虚拟化。在Linux中涉及namespace对系统的分区，通常与cgroup结合使用进行资源控制。而Docker容器和Pod依赖于进程模型和资源限制手段cgroups。因此，本项目从pod和docker容器进程模型和资源限制手段cgroups入手，研究容器编排平台工作单元的工作状态。

​	对于Docker而言：

1. 可以通过内核中针对cgroup的跟踪点，包括`cgroup:cgroup_setup_root` 、`cgroup:cgroup_attach_task`帮助调试容器的启动，同时可以使用BPF_TYPE_CGROUP_SKB程序类型，附加到cgroup入口点和出口点上处理网络数据包。

2. 可以通过PID命名空间来区分容器，nsproxy结构体中的`pid_ns_for_children`与`/proc/PID/ns/pid_for_children`符号链接指向的PID命名空间相匹配。

3. 可以通过UTS命名空间来区分容器，nsproxy结构体中的`uts_ns`与容器名称nodename一致。

​	对于Pod而言：

1. 可以通过网络命名空间识别kubernetes Pod，在同一个Pod中的容器共享同样的网络命名空间。
2. 可以通过Kubernetes的API server验证，通过PodName得到PodStatus，从而得到Pod对应的Container ID，在Docker下根据Container ID得到对应的Pid以及Children Pid对应的Container的子进程。

​	完成以上关联后，可以连接到k8s相关的resource，并且将fd操作的网络事件四元组信息进行提取。

## 3.3 数据收集和处理

​	将数据导出为易于处理的格式，如JSON、CSV等。

# 时间规划

预研阶段（06月15日-6月30日）

* [ ] 熟悉BPF开发知识，cilium/ebpf的开发知识和框架内容；
* [ ] 熟悉对Kubernetes Client的调用；
* [ ] 熟悉Linux网络栈的基础调用知识和流程；

研发第一阶段（07月01日 - 07月31日）

* [ ] 使用BPF对HTTP层数据进行采集：以Golang net/http库为基础，通过uprobe，获取HTTP相关信息，对于HTTP2，则需获取进行HPACK压缩前的明文数据；
* [ ] 通过Kubernetes Client，将指标与单机内Docker、单机内Pod进行关联，进行应用层关联；

研发第二阶段（08月01日 - 07月31日）

* [ ] 使用BPF对对基础指标进行追踪；
* [ ] 在添加负载或基础指标异常的情况下，使用BPF对进阶指标进行追踪；

研发第三阶段（09月01日 - 09月30日）

* [ ] 探索关联真实的网络请求，并针对数据分析深层延迟原因（如CPU、内存等内核调用二次导致）；
* [ ] 整理开发文档、数据可视化接口等。

