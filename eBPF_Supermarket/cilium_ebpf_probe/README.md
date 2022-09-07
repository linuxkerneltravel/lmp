# 基于 eBPF 的云原生场景下 Pod 性能监测

# 功能

1. 能够对指定namespace下的pod应用，可选择其中指定的容器，进行非侵入式的HTTP协议、HTTP2协议（gRPC）数据指标和报文头内容的监测。
2. Metrics监测内容以RED模型为标准，通过Prometheus和Grafana进行可视化。
3. 报文头内容可导出为xlsx形式。
4. 适用于原生Kubernetes集群。

# **运行**

### ENVIRONMENT

| Require    | Version          |
| ---------- | :--------------- |
| Linux      | 5.17.5           |
| CentOS     | 7.9.2009 (Core)  |
| GCC        | 11.2.1           |
| LLVM       | 11.0.0           |
| GoLang     | 1.18 Linux/amd64 |
| Kubernetes | v1.23.0          |
| Docker     | 20.10.14         |

#### 集群

1. 请保证运行环境中已部署Kubernetes、Docker环境。

2. 启动待监测的server pod

```bash
$ cd go/src
$ git clone https://github.com/linuxkerneltravel/lmp.git
$ cd lmp/eBPF_Supermarket/cilium_ebpf_probe
$ cd k8s_yaml
$ kubectl create namespace wyw
$ kubectl create -f g_server_pod.yaml
$ kubectl create -f http_server_pod.yaml
```

​		等待pod变更为Running状态。namespace可在yaml文件中进行自定义设计。

```bash
[root@k8s-master k8s_yaml]# kubectl get pods -n wyw
NAME         READY   STATUS    RESTARTS   AGE
grpcserver   1/1     Running   0          3m2s
httpserver   1/1     Running   0          3h46m
```

#### 可视化

​	为了进行可视化展示，需要通过以下流程对prometheus组件进行部署。

3. Docker启动普罗米修斯

```bash
$ docker run --name prometheus -v /etc/localtime:/etc/localtime -d -p 9090:9090 prom/prometheus:latest 
```

​	这里默认 Prometheus 开放 9090 端口，使用最新版官方镜像，当前最新版本为 v2.11.1，启动完成后，浏览器访问 http://yourIP:9090 即可看到默认 UI 页面。

4. Docker启动pushgateway

```bash
$ docker run --name pushgateway -v /etc/localtime:/etc/localtime -d -p 9091:9091 prom/pushgateway 
```

5. 将pushgateway和prometheus进行关联

​	Prometheus 默认配置文件 prometheus.yml 在[容器](https://cloud.tencent.com/product/tke?from=10680)内路径为` /etc/prometheus/prometheus.yml`添加prometheus.yml配置如下

```bash
...
- job_name: 'pushgateway'
    honor_labels: true
    static_configs:
      - targets: ['10.10.103.122:9091'] #pushgateway的端口
        labels:
          instance: pushgateway
```

​	完成后重启prometheus `docker restart prometheus`

6. Docker启动Grafana

```bash
$ docker run -d -p 3000:3000 --name grafana -v /etc/localtime:/etc/localtime grafana/grafana-enterprise:8.1.3
```

接下来打开 http://yourIP:3000 即可查看Grafana界面。并将对应的传送API接口修改，即可成功运行本探针程序。

#### BCC

​	请参看bcc官方教程在centos系统下的安装指导。

​	https://github.com/iovisor/bcc/blob/master/INSTALL.md#centos---source

#### 运行

​	回到`lmp/eBPF_Supermarket/cilium_ebpf_probe`目录下。

```bash
$ go run main.go
```

​	当出现如下报错时，显示gobpf和bcc版本不匹配所导致，在go.mod中修改gobpf@v0.0.0-20210109143822-fb892541d416为gobpf@v0.1.0或gobpf@v0.2.0至能运行即可。

```bash
/root/go/pkg/mod/github.com/iovisor/gobpf@v0.0.0-20210109143822-fb892541d416/bcc/module.go:230:132: not enough arguments in call to (_C2func_bcc_func_load)
        have (unsafe.Pointer, _Ctype_int, *_Ctype_char, *_Ctype_struct_bpf_insn, _Ctype_int, *_Ctype_char, _Ctype_uint, _Ctype_int, *_Ctype_char, _Ctype_uint, nil)
        want (unsafe.Pointer, _Ctype_int, *_Ctype_char, *_Ctype_struct_bpf_insn, _Ctype_int, *_Ctype_char, _Ctype_uint, _Ctype_int, *_Ctype_char, _Ctype_uint, *_Ctype_char, _Ctype_int)

```

​	针对主程序，设置了以下参数可供自定义，或可采用默认参数。

| Name         | Default                    | Usage                                |
| ------------ | -------------------------- | ------------------------------------ |
| --kubeconfig | /etc/kubernetes/admin.conf | absolute path to the kubeconfig file |
| --pod        | httpserver                 | pod name of http protocol            |
| --poduprobe  | grpcserver                 | pod name of http2 protocol           |
| --image1     | wyuei/http_server:v2.0     | docker image of http protocol        |
| --image2     | wyuei/grpc_server:latest   | docker image of http2 protocl        |
| --namespace  | Wow                        | namespace of your pod                |
| --nodename   | k8s-node2                  | node which your pods running on      |

运行成功后可见如下显示：

TODO

# 开发





# 项目实现细节

## 目录框架



# 未完成