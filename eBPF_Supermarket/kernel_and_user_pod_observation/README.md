# Kernel and User Pod Observation

本项目是一个基于 eBPF 的 pod 全面监控和可视化工具，能够同时在内核态和用户态提供高效强大的监控和可视化功能。

## 内核态监控

内核态监控功能可以通过

- 对 sidecar 和业务容器的网络收发事件进行捕获和分析
- 探查 pod 内部网络协议栈中数据包的流转情况
- 基于 Socket Redirection 的本机网络数据传输优化
- 获取 pod 内部的容器资源消耗（内存、CPU、网络、I/O）
- 在业界常用的可视化平台上进行可视化

### 环境配置

此处使用 minikube 进行测试环境搭建，完整的环境搭建过程可以参见 [CI 文件](../../.github/workflows/monitor_pod_combined.yml)或[部署文档](../sidecar/README.md#getting-started)。监控组建的搭建参看[监控组建部署文档](../sidecar/visualization/components/README.md)。

```shell
go build -o kupod main.go
kubectl label nodes minikube sidecar-demo-node=dev
kubectl apply -f https://raw.githubusercontent.com/linuxkerneltravel/lmp/develop/eBPF_Supermarket/sidecar/dev/sidecar-demo.yaml
```

### 使用方式

通过`kupod monitor kernel`可进入内核态监控部分，或可通过help命令进行查询。

| command | usage |
| ------------------------- | ------------------ |
| kupod monitor kernel all  | 启动网络协议栈事件和套接字事件监控探针 |
| kupod monitor kernel socket | 启动套接字事件监控探针 |
| kupod monitor kernel stack | 启动网络协议栈事件监控探针 |

与用户态监控有关的参数内容如下：

| flags           | usage                     |
| --------------- | ------------------------- |
| --exporter-port | 暴露指标使用的exporter的端口号 |
| --namespace     | 目标Pod所在命名空间 |
| --kubeconfig    | 集群kubeconfig文件路径 |
| --pod           | 目标Pod名称 |
| --pod-label     | 目标Pod的标签名 |
| --with-sockops  | 启用socket转发优化功能 |

#### 帮助命令

本项目的使用方式均可以通过对应的`--help`命令进行查阅。

```text
[root@node2 kernel_and_user_pod_observation]# ./kupod
KUPOD is an eBPF-based tool for monitoring and visualization of pods from user mode and kernel mode

Usage:
  kupod [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  monitor     Starts monitor for sidecar
  version     Print the version information

Flags:
  -h, --help   help for kupod

Use "kupod [command] --help" for more information about a command.
```

```text
[root@node2 kernel_and_user_pod_observation]# ./kupod monitor kernel --help
Starts monitor for pod.

Usage:
  kupod monitor kernel [flags]
  kupod monitor kernel [command]

Examples:
kupod monitor kernel all --pod sidecar-demo 

Available Commands:
  all         Monitor pod by all provided kernel tools.
  socket      Monitor pod by socket probes.
  stack       Monitor pod by network stack probes.

Flags:
  -h, --help   help for kernel

Global Flags:
      --exporter-port string   The exporter port of this monitor (default "8765")
      --force-minikube         Ignore Minikube checks and force Minikube mode
      --grpcimagename string   The docker in Pod to be monitored with which image for grpc (default "wyuei/grpc_server:latest")
      --grpcpod string         The pod to be monitored for grpc (default "grpcserver")
      --imagename string       The docker in Pod to be monitored with which image (default "wyuei/http_server:v2.0")
      --jaeger-agent string    Jaeger agent endpoint
      --kubeconfig string      The kubeconfig of k8s cluster (default "/etc/kubernetes/admin.conf")
      --namespace string       The namespace of pod to be monitored (default "default")
      --nodename string        The node where the pods running on (default "k8s-node2")
      --pod string             The pod to be monitored
      --pod-label string       The label of pod to be monitored
      --prometheus string      where the prometheus and push-gateway running on (default "10.10.103.122:9091")
      --sidecar-mode string    Specify the kind of sidecar: envoy, demo, or blur for now (default "blur")
      --veth string            The VETH name of pod to be monitored
      --with-sockops           Start monitor with sockops optimization

Use "kupod monitor kernel [command] --help" for more information about a command.
```

#### 执行命令

这里以同时对socket状态变化和内核网络协议栈的监测为例进行监测，指定了名为`sidecar-demo`的目标pod、用于暴露指标的exporter端口号为`8765`、jaeger-agent的目的地址和端口`10.10.102.102:8765`。

```text
[root@node kernel_and_user_pod_observation]# echo $VISUALIZE_IP
10.10.102.102
[root@node kernel_and_user_pod_observation]# ./kupod monitor kernel all --pod sidecar-demo --exporter-port 8765 --jaeger-agent ${VISUALIZE_IP}:8765
[PREFLIGHT] Got default kubeconfig from '/etc/kubernetes/admin.conf'
[PREFLIGHT] Got node name 'node'
[PREFLIGHT] Got container runtime 'docker://20.10.12'
Exporter at: http://0.0.0.0:8765
[INFO] Get target pod 'sidecar-demo' in namesapce 'default' on node 'node'
[INFO] Get 2 container(s) in this pod
[INFO] Got sidecar container 'sidecar-proxy' with image 'eswzy/sidecar-proxy:latest'
[INFO] Got 1 service container(s) in this pod
[INFO] Found pid 12679 from container 0cc6bc5b45c7bbfb4707a178fac3f6b9dd44798b5208499c2219706c03882502
[INFO] No child process founded for container 0cc6bc5b45c7bbfb4707a178fac3f6b9dd44798b5208499c2219706c03882502
[INFO] Found pid 12606 from container 8a61bc261d887041ec7eeaf356b0abbe6845b9e879d9c66f16d3c418954c3953
[INFO] Sidecar processes for BPF: [{"pid":12679}]
[INFO] Service processes for BPF: [{"pid":12606} {"pid":12645} {"pid":12646} {"pid":12647} {"pid":12648}]
[FINISHED] Get sidecar processes '[{"pid":12679}]'
[FINISHED] Get service processes '[{"pid":12606} {"pid":12645} {"pid":12646} {"pid":12647} {"pid":12648}]'
[INFO] got pod IP: 10.0.0.169, host IP: 10.10.102.103
TCP Connect started!
TCP Accept started!
Deep pod net started!
Deep pod net started!
```

### 内核态监控效果展示

对内核态的监控和可视化可以通过Grafana仪表盘的形式进行查看，对TCP网络请求的流水线可视化可以通过Jaeger进行查看。

![Kernel Mmetrics dashboard](./doc/img/kernel-metrics-dashboard.png)

![TCP Span](./doc/img/tcp-span.png)

## 用户态监控

通过`kupod monitor user`可进入用户态监控部分，或可通过help命令进行查询。

| command                   | usage              |
| ------------------------- | ------------------ |
| kupod monitor user all  | 启动http和grpc探针 |
| kupod monitor user http | 启动http探针       |
| kupod monitor user grpc | 启动grpc探针       |

与用户态监控有关的参数内容如下：

| flags           | usage                     |
| --------------- | ------------------------- |
| --kubeconfig    | kubernetes的默认配置地址  |
| --namespace     | 所要监控的Pod所在命名空间 |
| --pod           | http服务端的Pod名         |
| --imagename     | http服务端的镜像名        |
| --grpcpod       | grpc服务端的Pod名         |
| --grpcimagename | grpc服务端的镜像名        |
| --prometheus    | 普罗米修斯部署的IP地址    |
| --nodename      | 调度的Node处              |

### 用户态监控样例

#### 用户态监控帮助命令

```text
[root@k8s-node2 kernel_and_user_pod_observation]# ./kupod monitor user --help
For User Mode Monitor

Usage:
  kupod monitor user [flags]
  kupod monitor user [command]

Examples:
kupod monitor user all --pod sidecar-demo

Available Commands:
  all         Monitor pod by all provided user tools.
  grpc        Starts monitor for pod by GRPC probes.
  http        Starts monitor for pod by HTTP probes.

Flags:
  -h, --help   help for user

Global Flags:
      --exporter-port string   The exporter port of this monitor (default "8765")
      --force-minikube         Ignore Minikube checks and force Minikube mode
      --grpcimagename string   The docker in Pod to be monitored with which image for grpc (default "wyuei/grpc_server:latest")
      --grpcpod string         The pod to be monitored for grpc (default "grpcserver")
      --imagename string       The docker in Pod to be monitored with which image (default "wyuei/http_server:v2.0")
      --jaeger-agent string    Jaeger agent endpoint
      --kubeconfig string      The kubeconfig of k8s cluster (default "/etc/kubernetes/admin.conf")
      --namespace string       The namespace of pod to be monitored (default "default")
      --nodename string        The node where the pods running on (default "k8s-node2")
      --pod string             The pod to be monitored
      --pod-label string       The label of pod to be monitored
      --prometheus string      where the prometheus and push-gateway running on (default "10.10.103.122")
      --sidecar-mode string    Specify the kind of sidecar: envoy, demo, or blur for now (default "blur")
      --with-sockops           Start monitor with sockops optimization
```

#### 用户态监控效果展示

```text
[root@k8s-node2 kernel_and_user_pod_observation]# ./kupod monitor user all --namespace wyw --pod httpserver --grpcpod grpcserver --prometheus 10.10.103.122
There are 2 pods in the cluster in wyw namespace
Found pod httpserver in namespace wyw
[INFO] Found pid 12824 from container 4a3bb7f58d6671b3c5440d1722072d95aafe27d3aed4f6b6b133677a9468f747
[INFO] No child process founded for container 4a3bb7f58d6671b3c5440d1722072d95aafe27d3aed4f6b6b133677a9468f747
get specific docker of image  wyuei/http_server:v2.0
get pod httpserver Pid and Attach Kprobe
Found pod grpcserver in namespace wyw
get specific docker of image  wyuei/grpc_server:latest
get pod grpcserver Merge Path and Attach Uprobe
Attach 1 uprobe on  /var/lib/docker/overlay2/2decd6258eb639d8b9815a9f9dc185e24804d9a475f2c413425d0104c5f539c7/merged/go/src/grpc_server/main
kprobe for http begins...
uprobe for http2 grpc begin...
HTTP2 from grpcserver [1](stream id:1)::status:200,content-type:application/grpc,:method:POST,:scheme:http,:path:/greet.Greeter/SayHello,:authority:10.0.3.130:50051,content-type:application/grpc,user-agent:grpc-go/1.48.0,te:trailers,grpc-timeout:4996954u,weight:0,grpc-status:0,grpc-message:,
HTTP2 from grpcserver [2](stream id:3)::method:POST,:scheme:http,:path:/greet.Greeter/SayHello,:authority:10.0.3.130:50051,content-type:application/grpc,user-agent:grpc-go/1.48.0,te:trailers,grpc-timeout:4999906u,weight:0,:status:200,content-type:application/grpc,grpc-status:0,grpc-message:,
HTTP from httpserver [1]:StatusCode: 200, Len: 35, ContentType: [text/plain; charset=utf-8], Body: Resonse:The request was successful.
HTTP from httpserver [2]:StatusCode: 200, Len: 35, ContentType: [text/plain; charset=utf-8], Body: Resonse:The request was successful.
```
