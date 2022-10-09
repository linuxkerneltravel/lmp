# Kernel and User Pod Observation

## Getting Started

```shell
go build -o kupod main.go
kubectl label nodes minikube sidecar-demo-node=dev
kubectl apply -f https://raw.githubusercontent.com/linuxkerneltravel/lmp/develop/eBPF_Supermarket/sidecar/dev/sidecar-demo.yaml
sudo ./kupod monitor all --pod sidecar-demo
```
### 用户态监控指令

通过`./kupod monitor user`可进入用户态监控部分，或可通过help命令进行查询。

| command                   | usage              |
| ------------------------- | ------------------ |
| ./kupod monitor user all  | 启动http和grpc探针 |
| ./kupod monitor user http | 启动http探针       |
| ./kupod monitor user grpc | 启动grpc探针       |

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

#### example

```bash
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

