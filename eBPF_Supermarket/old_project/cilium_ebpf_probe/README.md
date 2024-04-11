# 基于 eBPF 的云原生场景下 Pod 性能监测

# 功能

1. 能够对指定namespace下的pod应用，可选择其中指定的容器，进行非侵入式的HTTP协议、HTTP2协议（gRPC）数据指标和报文头内容的监测。
2. Metrics监测内容以RED模型为标准，通过Prometheus和Grafana进行可视化。
3. 报文头内容可导出为xlsx形式。
4. 适用于原生Kubernetes集群。

# **运行**

## ENVIRONMENT

| Require    | Version          |
| ---------- | :--------------- |
| Linux      | 5.17.5           |
| CentOS     | 7.9.2009 (Core)  |
| GCC        | 11.2.1           |
| LLVM       | 11.0.0           |
| GoLang     | 1.18 Linux/amd64 |
| Kubernetes | v1.23.0          |
| Docker     | 20.10.14         |

### 集群

1. 请保证运行环境中已部署Kubernetes、Docker、Go等环境。Kubernetes请勿以Kind、K3S等其他形式部署。

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

### 可视化

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

### BCC

7. 请参看bcc官方教程在centos系统下的安装指导。

​	https://github.com/iovisor/bcc/blob/master/INSTALL.md#centos---source

### 运行

8. 回到`lmp/eBPF_Supermarket/cilium_ebpf_probe`目录下。

```bash
$ go run main.go
```

​	当出现如下报错时，显示gobpf和bcc版本不匹配所导致，在go.mod中修改gobpf@v0.0.0-20210109143822-fb892541d416为gobpf@v0.1.0或gobpf@v0.2.0至能运行即可。

```bash
/root/go/pkg/mod/github.com/iovisor/gobpf@v0.0.0-20210109143822-fb892541d416/bcc/module.go:230:132: not enough arguments in call to (_C2func_bcc_func_load)
        have (unsafe.Pointer, _Ctype_int, *_Ctype_char, *_Ctype_struct_bpf_insn, _Ctype_int, *_Ctype_char, _Ctype_uint, _Ctype_int, *_Ctype_char, _Ctype_uint, nil)
        want (unsafe.Pointer, _Ctype_int, *_Ctype_char, *_Ctype_struct_bpf_insn, _Ctype_int, *_Ctype_char, _Ctype_uint, _Ctype_int, *_Ctype_char, _Ctype_uint, *_Ctype_char, _Ctype_int)
```

​	针对`main.go`，设置了以下参数可供自定义，或可采用默认参数。

| Name         | Default                    | Usage                                |
| ------------ | -------------------------- | ------------------------------------ |
| --kubeconfig | /etc/kubernetes/admin.conf | absolute path to the kubeconfig file |
| --pod        | httpserver                 | pod name of http protocol            |
| --poduprobe  | grpcserver                 | pod name of http2 protocol           |
| --image1     | wyuei/http_server:v2.0     | docker image of http protocol        |
| --image2     | wyuei/grpc_server:latest   | docker image of http2 protocl        |
| --namespace  | Wow                        | namespace of your pod                |
| --nodename   | k8s-node2                  | node which your pods running on      |

​	运行成功后可见如下显示：

```bash
[root@k8s-node2 cilium_ebpf_probe]# go run main.go
There are 2 pods in the cluster in wyw namespace
Found pod httpserver in namespace wywach Uprobe
[INFO] Found pid 15061 from container d7e04981aacd20a98901d8f41f3ac810b113693023817b170be8462a79f14eb8a296c35/merged/go/src/grpc_server/main
[INFO] No child process founded for container d7e04981aacd20a98901d8f41f3ac810b113693023817b170be8462a79f14eb8
get specific docker of image  wyuei/http_server:v2.0
get pod httpserver Pid and Attach Kprobe
Found pod grpcserver in namespace wyw
get specific docker of image  wyuei/grpc_server:latest
get pod grpcserver Merge Path and Attach Uprobe
Attach 1 uprobe on  /var/lib/docker/overlay2/24eaa194ebf14c9bc0db8d933ed15ffe990fda059d7c69990a1d74134a296c35/merged/go/src/grpc_server/main
kprobe for http begins...
uprobe for http2 grpc begin...
```

**捕获HTTP数据**

​	进入cilium_ebpf_probe目录下的http_client路径，提供了简单的HTTP客户端，调用进行访问。

```bash
[root@k8s-node2 cilium_ebpf_probe]# cd http_client/
[root@k8s-node2 http_client]# ls
main.go
[root@k8s-node2 http_client]# go run main.go
```

​	主程序捕捉到的报文信息如下：

```bash
HTTP from httpserver [1]:StatusCode: 200, Len: 35, ContentType: [text/plain; charset=utf-8], Body: Resonse:The request was successful.
HTTP from httpserver [2]:StatusCode: 200, Len: 35, ContentType: [text/plain; charset=utf-8], Body: Resonse:The request was successful.
```

**捕获gRPC数据**

​	进入cilium_ebpf_probe目录下的grpc_client路径，提供了简单的gRPC客户端，调用进行访问。

```bash
[root@k8s-node2 cilium_ebpf_probe]# cd grpc_client/
[root@k8s-node2 grpc_client]# ls
main.go
[root@k8s-node2 grpc_client]# go run main.go --count=2
2022/09/08 13:56:29 Greeting: Hello world
2022/09/08 13:56:29 Greeting: Hello world
```

​	主程序捕获报文信息如下：

```bash
HTTP2 from grpcserver [1](stream id:1)::method:POST,:scheme:http,:path:/greet.Greeter/SayHello,:authority:10.0.3.236:50051,content-type:application/grpc,user-agent:grpc-go/1.48.0,te:trailers,grpc-timeout:4975471u,weight:0,:status:200,content-type:application/grpc,grpc-status:0,grpc-message:,
HTTP2 from grpcserver [2](stream id:3)::method:POST,:scheme:http,:path:/greet.Greeter/SayHello,:authority:10.0.3.236:50051,content-type:application/grpc,user-agent:grpc-go/1.48.0,te:trailers,grpc-timeout:4999852u,weight:0,:status:200,content-type:application/grpc,grpc-status:0,grpc-message:,
```

## 结果输出

​	本项目将捕获到的HTTP层请求，解析后分析其请求延时、计数和状态码，形成Metrics传递至pushgateway。报文部分则输出至xlsx文件。

### Metrics类型

#### HTTP Spend

​	标识一次HTTP响应请求的延时，以其push至pushgateway的时间作为时间戳。

​	使用Histogram类型，有20个bucket。job名定义为`HTTPSpend`，为其打上podname和instance的label。

```go
var histogramRegistered = prometheus.NewHistogram(
prometheus.HistogramOpts{
Name:    "http_spend",
Help:    "A histogram of normally distributed http spend time(us).",
Buckets: prometheus.LinearBuckets(0, 800, 20), //start,width,count
},
)
func Histogram_Push(podname string, spendtime int64, gotime int64) {
histogramRegistered.Observe(float64(spendtime / 1000 / 1000)) //ns/1000/1000
if err := push.New("http://10.10.103.122:9091", "HTTPSpend"). // push.New("pushgateway地址", "job名称")
Collector(histogramRegistered).
Grouping("podname", podname).Grouping("instance", "spendtime"). // 给指标添加标签，可以添加多个
Push(); err != nil {
fmt.Println("Could not push completion time to Pushgateway:", err)
}
}
```

#### HTTP Status Code

​	收集HTTP响应的状态码。

​	为了方便计数，为每一类型的状态码都定义一种Gauge类型，每出现一次状态码，在相应的Gauge值内进行自加。job名定义为`HTTPStatus`，为其打上podname、instance和相应status code的label。

```go
var statusMap map[int]prometheus.Gauge
statusMap = make(map[int]prometheus.Gauge)
statusMap[200] = prometheus.NewGauge(prometheus.GaugeOpts{
Name: "http_status_code_200",
Help: "Current status of the http protocol.",
})
...
func Gauge_Push(podname string, statuscode int, gotime int64) {
statusMap[statuscode].Add(1)
if err := push.New("http://10.10.103.122:9091", "HTTPStatus"). // push.New("pushgateway地址", "job名称")
Collector(statusMap[statuscode]).
Grouping("podname", podname).Grouping("instance", "statuscode").Grouping("StatusCode", strconv.Itoa(statuscode)).
Push(); err != nil {
fmt.Println("Could not push completion time to Pushgateway:", err)
}
}
```

#### gRPC Spend

​	标识一次gRPC响应请求的延时。

​	使用Histogram类型，job名定义为`GRPCSpend`，原理与HTTP Spend一致。

#### gRPC Status Code

​	收集gRPC响应的状态码。

​	使用Gauge类型，job名定义为`GRPCStatus`，原理与HTTP Status Code一致。

### Grafana可视化图表

​	本项目展示内容可通过Prometheus结合Grafana进行可视化展示，可定制以下图表内容：

1. **HTTP Delay Distributation**

​	展示HTTP响应延时分布的HeatMap，在Delay根据Bucket的分布上加上时间维度，显示随着时间，Delay在各个区间内分布的趋势。

```sql
A
Metrics browser > http_spend_bucket
```

2. **HTTP Request Count**

​	展示HTTP响应请求计数的Time Series，显示随着时间请求变化的趋势。在上文Metrics指标中虽然没有直接对count进行统计，但可通过Histogram直接完成当前时刻的计数。

```sql
A
Metrics browser > http_spend_count
```

3. **HTTP Request Delay**

​	展示HTTP响应延时的区间分布的Histogram。

```sql
A
Metrics browser > http_spend_bucket
```

4. **HTTP StatusCode**

​	展示HTTP响应请求的Status Code的统计Pie Chart。需要将上文Metrics指标中同一Job下，lable StatusCode不同的实例分别载入。

```sql
A
Metrics browser > http_status_code_200
Legend code_200
Format Time series
B
Metrics browser > http_status_code_400
Legend code_400
Format Time series
C
Metrics browser > http_status_code_404
Legend code_404
Format Time series
...
```

5. **gRPC Request Count**

​	展示gRPC响应请求计数的Time Series，显示随着时间请求变化的趋势。

```sql
A
Metrics browser > grpc_spend_count
```

6. **gRPC Request Delay**

​	展示gRPC响应延时的区间分布的Histogram。

```sql
A
Metrics browser > grpc_spend_bucket
```

7. **gRPC StatusCode**

​	展示gRPC响应请求的Status Code的统计Pie Chart。

```SQL
A
Metrics browser > gRPC_status_0
Legend code_0
Format Time series
```

### XLSL输出

​	本项目捕捉到报文相关信息，由于是文本形式，因此考虑XLSX形式导出。

1. **HTTP报文信息导出**

​	导出至`httpserver.xlsx`中，属性列为：

- statuscode
- contentlength
- content-type
- body

2. **gRPC报文信息导出**

​	导出至`BookUprobe.xlsx`中，属性列为：

- streamID
- method
- scheme
- path
- authority
- content-type
- user-agent
- te
- grpc-timeout
- weight
- status
- content-type
- grpc-status
- grpc-message

# 项目实现

## 目录框架

```
-------cilium_ebpf_probe                                                              
   |---- cluster_utils            cluster Helper函数     
   |---- Dockerfile               server端镜像Dockerfile文件
   |---- cuprobe									uprobe for c example
   |---- grpc_client              grpc客户端              
   |---- grpc_server              grpc服务端              
   |---- http2_tracing            http2 uprobe部分       
   |   \- bpf_program.go             bpf程序             
   |    \- http2_trace_uprobe.go     用户态程序             
   |---- http_client              http客户端              
   |---- http_server              http服务端              
   |---- http_kprobe              http kprobe部分        
   |   \- bpf_program.go             bpf程序             
   |    \- main.go                   用户态程序             
   |---- k8s_yaml                 kubernetes部署Pod文件    
   |---- proto                    grpc proto           
   |- go.mod                                           
   +- main.go                     程序入口             
```

## 技术细节

请参看Document的技术实现部分。

# 待实现

1. 目前本项目针对gRPC协议，只进行了HTTP2标头的追踪，而不是数据帧。对于跟踪数据帧，需要识别接受数据帧作为参数的其他Golang net/http2 库函数，并确定相关数据结构的内存布局。
2. 目前本项目只针对golang启动的gRPC服务器完成报文头的uprobe点追踪。对于Java、C语言，由于用户态实现方式不同，需要进行重新寻找uprobe点、确定不同编程语言的函数传参方式等工作。
3. 目前本项目只针对原生Kubernetes完成了Uprobe点、Kprobe点的添加，对于以Minikube、Kind等其他形式部署的集群，由于存在不同命名空间内Pid映射、文件挂载位置迁移等问题，有待继续完善开发。

## Tips

​	在cuprobe文件夹下，有一个简单的使用gobpf为C程序test添加uprobe、获取其中的函数`hello`第一个参数的example。

1. 对其中的test.c，一个简单的C程序，使用`gcc test.c -o test`将C程序编译为可执行文件。

```C
#include "stdio.h"
static int hello(int a,int b){
  ...
}
int main(int argc,char *argv[])
{
		...
    c=hello(a,b);
  	...
}
```

2. 使用`objdump -t test` 或者`nm test`命令，对可执行文件中的symbol进行验证，确认想要Attach Uprobe的`hello`函数symbol确实可以被搜寻到。

```cmake
0000000000000000 l    df *ABS*	0000000000000000              test.c
0000000000401136 l     F .text	0000000000000014              hello
0000000000000000 l    df *ABS*	0000000000000000              crtstuff.c
000000000040217c l     O .eh_frame	0000000000000000              __FRAME_END__
0000000000000000 l    df *ABS*	0000000000000000
0000000000403e20 l       .init_array	0000000000000000              __init_array_end
0000000000403e28 l     O .dynamic	0000000000000000              _DYNAMIC
0000000000403e18 l       .init_array	0000000000000000              _
```

3. 运行trace uprobe程序，使用指令`go run trace.go --binary binaryProg`，其中`binaryProg`为当前可执行文件到绝对地址。并同时运行test文件。添加uprobe成功。

```bash
#ssh1
[root@k8s-node2 cuprobe]# ./test
first 1 second 2 result 3
#ssh2
[root@k8s-node2 cuprobe]# go run trace.go
uprobe for C begin...
Value = 1
```

​	为C语言grpc服务器添加uprobe诸如以上流程，欢迎感兴趣的同学加入开发。

# 参考引用

- https://blog.px.dev/ebpf-http-tracing/
- https://blog.px.dev/ebpf-openssl-tracing/
- https://blog.px.dev/ebpf-http2-tracing/
- https://zhuanlan.zhihu.com/p/27339191
- https://cch123.gitbooks.io/duplicate/content/part3/translation-details/function-calling-sequence/calling-convention.html
- https://yunlzheng.gitbook.io/prometheus-book/parti-prometheus-ji-chu/promql/prometheus-promql-best-praticase
- https://go.googlesource.com/proposal/+/master/design/40724-register-calling.md
- https://yunlzheng.gitbook.io/prometheus-book/parti-prometheus-ji-chu/promql/prometheus-promql-best-praticase