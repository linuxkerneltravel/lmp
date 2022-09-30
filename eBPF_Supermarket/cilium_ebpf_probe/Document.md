# 项目信息

## 项目名称

​	基于eBPF的云原生场景下Pod性能监测

## 方案描述

​	本项目要求为基于 eBPF 实现内核级别的细粒度数据采集。首先要求从 Linux 内核中提取到网络相关的系统调用，并与具体 Pod 关联，在此基础之上，需要对 Pod 内容进行进程/线程粒度的网络数据采集和处理，并映射到用户态 Pod 进行可视化展示，所有功能需要对接到社区项目LMP中。

​	因此，本项目实现了基于eBPF，针对服务应用实现了无侵入式的服务端HTTP流量的可见性。分别对HTTP协议、HTTP2协议都进行了明文指标的捕获和组装，并将指标内容和集群内业务层Pod、Namespace相关联，进行RED指标进行网络状态的评估，并使用Prometheus实现了结果可视化。

## 时间规划

**预研阶段（06月15日-6月30日）**

* [x] 熟悉BPF开发知识，bcc的开发知识和框架内容；
* [x] 熟悉对Kubernetes Client的调用，Kubernetes Client调用API Server可获得的相关数据；
* [x] 熟悉Linux网络栈的基础调用知识和流程；
* [x] 熟悉Kubernetes、Docker的基本原理

**研发第一阶段（07月01日 - 07月31日）**

* [x] 搭建HTTP、gRPC服务器，进行容器化部署；
* [x] 使用BPF对HTTP层数据进行采集：以Golang net/http库为基础，通过uprobe，获取HTTP相关信息；对于gRPC协议，则需获取进行HPACK压缩前的明文数据；
* [x] 通过Kubernetes Client，将指标与单机内Docker、单机内Pod进行关联，进行应用层关联；

**研发第二阶段（08月01日 - 08月31日）**

* [x] 模拟HTTP服务端和gRPC的各类型状态码，进行请求压测；
* [x] 对HTTP层数据指标建模，统计延时、状态码、速率等，以RED模型建模评估；
* [x] 部署可视化组件Prometheus、Grafana，并部署push gateway，进行BPF捕获数据的上传；
* [x] 增添可获取的指标内容类型；

**研发第三阶段（09月01日 - 09月31日）**

* [x] 完成CI自动测试文件；
* [x] 代码结构整理优化；
* [x] 完成项目总结文档的书写。

# 实现方案

## eBPF的用处

​	在分布式应用程序、大规模集群环境下，实现HTTP流量的可见性，可用于性能、功能和安全监控等用处。

​	许多应用程序通过利用中间件向应用程序中的 HTTP 请求添加跟踪或日志记录来对HTTP协议数据进行跟踪，或是用wireshark、fiddler等工具。而利用eBPF krpobes捕获HTTP数据，以较稳定的系统调用的跟踪，可实现与应用无关的非侵入式、长期有效的效果，且能进行可编程的定制化信息采集。

​	而针对HTTP2而言，HTTP2 的专用标头压缩算法HPACK会使跟踪 HTTP2 使用典型的网络跟踪器无效。例如当Wireshark在消息流启动后运行，由于丢失最初的 HTTP2 帧 ，就无法解码 HTTP2 HEADERS。而通过 eBPF uprobes 直接跟踪应用程序内存中的明文数据可以解决 HPACK 问题。

## 项目模块划分

![image-20220907150020763](https://raw.githubusercontent.com/WYuei/uPic/master/2022/09/image-20220907150020763.png)

1. 通过BPF Program，提取线程级别的流量数据，并在用户态还原组装为HTTP协议内容。
2. 通过Kubernetes API Server和Container Daemon，将集群中的业务资源（Namespace、Pod等），和本质线程以及对应数据关联。
3. 通过Prometheus和Grafana，实现捕获流量可视化。

## 技术实现

### 1. HTTP数据

​    当HTTP服务接收到请求时会有accept/read/write/close等函数执行，这些函数最终执行内核的系统调用，本质上是对某一连接代表的文件描述符进行读写操作。因此，关联进程号和文件描述符fd，即可关联同一个请求或响应。

![image-20220907150204550](https://raw.githubusercontent.com/WYuei/uPic/master/2022/09/image-20220907150204550.png)

​	建立一个简单的HTTP服务器，并使用perf trace -p PID命令追踪该服务器的相关系统调用，可以看到的确有对统一文件描述符的操作指令。

![image-20220907150248502](https://raw.githubusercontent.com/WYuei/uPic/master/2022/09/image-20220907150248502.png)

 	在服务器发送HTTP响应时。典型的响应流程如下系统调用。

- `accept4`：当有新的incoming connection进入时，会创建一个新的文件描述符，作为新连接的标识符。
- `write`：将需要输出的数据写入文件描述符。
- `close`：关闭连接。

#### 系统调用probe点

```C
int accept4(int sockfd, struct sockaddr *addr,socklen_t *addrlen, int flags);
```

- `Sockfd` 使用的文件描述符；
- `addr` 存放结构体信息的首地址
- `addrlen` 存放地址信息的结构体大小
- `flags` 用于设置标识，例如设置阻塞或者非阻塞模式

**分别为accept4函数，添加Kprobe和Kretprobe**：

**Kprobe：**

- 将addrlen作为buff的size，从addr中提取socket相关信息所在的地址；

**Kretprobe：**

- 获取函数返回值fd作为接下来的连接唯一文件标识符，并存储BPF_MAP中，将socket的addr、bufsize等信息推送至Ring Buffer。调用`bpf_ktime_get_ns`，获取系统相对时间，作为处理开始时间。

```C
size_t write(int fildes,const void *buf,size_t nbytes);
```

​	系统调用 `write `的作用是把缓冲区 buf 的前 nbytes 个字节写入与**文件描述符 fildes** 关联的文件中

**添加Kprobe：**

- 由于BPF堆栈尺寸限制，多属性的结构体通过BPF_PERCPU_ARRAY进行传递。因此同一HTTP请求在不同系统调用之间的数据流动，需要根据fd在BPF_PERCPU_ARRAY中进行比对关联。
- 通过write函数中的fd和`bpf_get_current_pid_tgid`匹配当前的pid，可以匹配到socket的抓取内容。将buf作为socket通信内容，count是占用的bytes数，得到文件描述符的相关信息和数据信息，BPF_PERF_OUTPUT将其传送至用户态。

```C
int close(int fildes);
```

​	系统调用 `close` 可以用来终止文件描述符fildes与其对应文件之间的关联。当`close`系统调用成功时，返回 0，文件描述符被释放并能够重新使用；调用出错，则返回 -1。

**添加Kprobe：**

- 通过close关闭fd对应的socket，本次连接结束，并在BPF_MAP中删除fd对应的信息，停止跟踪。
- 通过`bpf_ktime_get_ns`获取系统时间，作为处理结束时间。

#### BPF数据结构

​	针对以上可提取的probe点数据，BPF需要以下数据结构来进行信息的存储和Ringbuffer的传递。

```C
struct attr_t {
    int event_type;
    int fd; 
    int bytes;
    int msg_size;
    u64 start_ns;
    u64 end_ns;
  } attr;
BPF_PERCPU_ARRAY(write_buffer_heap, struct syscall_write_event_t, 1);      
BPF_HASH(active_fds, int, bool);
BPF_HASH(active_sock_addr, u64, struct addr_info_t);
```

#### 用户态组装

​	将不同探针中抓取的调用时间和信息，通过唯一的fd文件标识符作为key，根据pid进行标识收集。并为每一种探针添加类型索引，以便通过perf push到用户态后，根据事件类型重新进行组装，根据事件eventType完成结构体MessageInfo的拼接。

```Go
type MessageInfo struct {
	GoTime     int64
	Time_ns    int64
	SocketInfo []byte
	Buf        bytes.Buffer
}
```

​	得到从内存中拷贝得到的数据内容后，需要使用net/http库中的`ReadResponse`函数进行解码，从而能拿到具有可读性的Response回应。

### 2. HTTP2数据

​    HTTP/2 是 HTTP 协议自 1999 年 HTTP 1.1 发布后的首个更新，主要基于 SPDY 协议。

​	HPACK算法是新引入HTTP/2的一个算法，用于对HTTP头部做压缩。其原理在于：客户端与服务端维护一份共同的静态字典，并根据先入先出的原则，维护一份可动态添加内容的共同动态字典。

![image-20220907152356647](https://raw.githubusercontent.com/WYuei/uPic/master/2022/09/image-20220907152356647.png)

​	因此在报文头数据到达内核时，已经被压缩加密，无法直接通过kprobe的方式从系统调用中读取数据内容，而需通过uprobe，在用户应用程序中的相关压缩函数前直接进行捕获。

​	以golang1.18搭建grpc服务器，在google/grpc共享库函数中添加uprobe。

#### 应用函数probe点

```go
func (t *http2Server) operateHeaders
(frame *http2.MetaHeadersFrame, handle func(*Stream),traceCtx func(context.Context, string) context.Context)
//symbol
google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders
```

​	通过本函数得到服务器收到的报文头内容。其中，主要读取第一个参数frame中Fields的内容。再从相应的寄存器(si寄存器)中读取函数入参即可。

​	在本probe点中，可获得数据有：

- frame.Fields中的报文头数据，如method、scheme、useragent等
- frame.FrameHeader.StreamID
- frame.Priority.Weight

![image-20220907153018467](https://raw.githubusercontent.com/WYuei/uPic/master/2022/09/image-20220907153018467.png)

```Go
func (l *loopyWriter) writeHeader(streamID uint32, endStream bool, hf []hpack.HeaderField, onWrite func())
//symbol
google.golang.org/grpc/internal/transport.(*loopyWriter).writeHeader
```

​	通过本函数得到服务器即将发出的报文头内容。其中，读取第三个参数 hf 的内容，它是 HeaderField 的切片。

​	在本probe点中，可获得数据有：

- hf中的报文头切片，如status、content-type等
- streamID
- endStream

![image-20220907153039460](https://raw.githubusercontent.com/WYuei/uPic/master/2022/09/image-20220907153039460.png)

#### BPF数据结构

​	对于operateHeaders和writeHeader两个函数probe点，能拿到的信息均为Key-Value类型，但也有一定的差异，因此需要为两者定义各自的数据结构。

```C
struct write_header_t{
	struct go_grpc_http2_header_event_t event[2];
  int32_t sid;
	int64_t ns;
};
struct operator_header_t{
	struct go_grpc_http2_header_event_t event[8];
	int32_t sid;
  int8_t w;
	int64_t ns;
};
BPF_PERCPU_ARRAY(write_header_heap,struct write_header_t,1);
BPF_PERCPU_ARRAY(operator_header_heap,struct operator_header_t,1);
BPF_PERF_OUTPUT(write_header_events);
BPF_PERF_OUTPUT(operator_header_events);
BPF_HASH(timecount, u64, u64,1);
```

​	读取部分寄存器内容时，由于寄存器值为地址，需要使用`bpf_probe_read`来从指定地址读取相关数据,如下为从bx寄存器中读取frame变量的地址，考虑到第一个参数为`loopywriter`的指针，因此需要加8字节。

```C
  void* frame_ptr=(void*)ctx->bx;
  void* fields_ptr;
  bpf_probe_read(&fields_ptr, sizeof(void*), frame_ptr + 8);
```

#### 用户态组装

​	在HTTP2协议中，同一个Stream请求拥有同样的StreamID，而endStream代表了当前流的结束标识，可根据此精确的得到一个Stream请求的延时、调用时间，把用户态零散的指标内容进行请求的组装。因此，使用streamID作为Key的map，即可完成单个流请求的辨识。

```go
type formatedHeaderevent struct {
	Key   string
	Value string
}
var requestSlice        map[int32][]formatedHeaderevent
```

### 3.集群连接

​    Docker容器本质就是一种通过Linux Namespace限制、并且被Cgroups限制CPU等资源的特殊进程，并且通过联合挂载和chroot得到自己的新的根目录。

​	因此，想要将系统调用级别的调用信息、用户程序的Uprobe和集群业务信息联系在一起，只需要将集群中的Pod资源所代表的Docker Inspect表示的容器进程和容器用户程序所在位置找到，就可为其添加BPF程序。

​	通过golang的client-go包将本地与集群进行连接，得到clentset调用客户端。

```go
var kubeconfig *string
kubeconfig = flag.String("kubeconfig", "/etc/kubernetes/admin.conf", "absolute path to the kubeconfig file")
flag.Parse()
config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
//通过参数（master的url或者kubeconfig路径）和BuildConfigFromFlags方法来获取rest.Config对象，
if err != nil {
	panic(err.Error())
}
clientset, err := kubernetes.NewForConfig(config)
//通过*rest.Config参数和NewForConfig方法来获取clientset对象，clientset是多个client的集合，每个client可能包含不同版本的方法调用
if err != nil {
	panic(err.Error())
}
```

​	通过API Srever提供的接口，可以根据指定的namespace和pod name获取pod信息。

```go
p, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), pod, metav1.GetOptions{})
```

​	**Kprobe：**通过API Server获取相关Node的容器运行时客户端（本场景中均为docker），即可根据pod对应的containerID，从docker的ContainerInspect中获取Pid。

​	**Uprobe：**可通过同样的ContainerInspect中的GraphDriver.Data["MergedDir"]，即相关pod容器在本机上实际挂载的文件位置，获得所需的共享库和挂载位置

![image-20220907153127805](https://raw.githubusercontent.com/WYuei/uPic/master/2022/09/image-20220907153127805.png)

### 4.指标监控

​	以RED模型基准作为统计、计算标准。

- **(请求)速率**：服务每秒接收的请求数。
  - 根据服务端每秒接受处理的请求数统计。

- **(请求)错误**：每秒失败的请求数。
  - 化用为对Status Code的统计。

- **(请求)耗时**：每个请求的耗时。

  -  针对HTTP协议数据，因此从accept4函数接收一个新连接开始、到close函数关闭文件描述符断开连接作为请求处理耗时。并在用户程序里以eventBegin类型事件出现时的Go Time作为系统绝对时间。

  -  针对HTTP2协议数据，从operateHeaders函数接收头帧开始、到writeHeader函数写入发送帧作为请求处理耗时。在用户态通过两个channel，分别存储开始事件和结束时间；并将operateHeaders中提取event时的Go Time作为系统绝对时间。

#### 状态码模拟

​	为了更好的展示监测效果，在HTTP server端进行status code的模拟，使用随机rand的方式选取返回响应的状态，有以下类别：

| Status Code | Reason                      |
| ----------- | --------------------------- |
| 200         | The request was successful. |
| 400         | Bad Request.                |
| 401         | Unauthorized.               |
| 404         | Not Found.                  |
| 502         | Bad Gateway.                |
| 504         | Gateway Time-out.           |

#### 高频请求

​	使用http client端向server端高频发生请求时，会发生连接合并为长连接现象，影响多次多段的监测流效果，需要在使用client初始化时，关闭自动长连接选项。

```go
client := &http.Client{
				Transport: &http.Transport{
					DialContext: (&net.Dialer{
						KeepAlive: 0, // 修改为 0 可以生效
					}).DialContext,
				}}
```

### 5.可视化

​    以Docker的方式配置Prometheus、Pushgateway、Grafana。

​	Metrics数据主要以两种类型存储：

1. Gauge 代表一种样本数据可以任意变化的指标，即可增可减。
2. Histogram在一段时间范围内对数据进行采样（通常是请求持续时间或响应大小等），并将其计入可配置的存储桶（bucket）中，后续可通过指定区间筛选样本，也可以统计样本总数。

![image-20220907153253111](https://raw.githubusercontent.com/WYuei/uPic/master/2022/09/image-20220907153253111.png)

![图片1](https://raw.githubusercontent.com/WYuei/uPic/master/2022/09/图片1.png)



# 项目总结

## 项目产出

1. 确定本项目的详细功能要求。
2. 完成对云原生集群中Pod层级的应用层观测，可初步实现HTTP、HTTP2的协议的初步非侵入式捕获结果。
3. 完成结果的可视化展示，进行指标效果的建模，成功对接入lmp项目。
4. 产出详细的技术文档和指引文档，提供可拓展的features。

## 方案进度

成功按照原本时间规划和方案设计，完成本项目。

1. 能够对指定namespace下的pod应用，可选择其中指定的容器，进行非侵入式的HTTP协议、HTTP2协议（gRPC）数据指标和报文头内容的监测。
2. Metrics监测内容以RED模型为标准，通过Prometheus和Grafana进行可视化。
3. 报文头内容可导出为xlsx形式。

## 遇到的问题及解决方案

### 1.UretProbe问题

​	基于Golang语言的net/http库，观察到每次HTTP 请求完成时都会调用`net/http.(*response).finishRequest`函数，因此打算使用Uretprobe获取`finishRequest`的返回值，根据BPF程序里的`pt_regs->sp`用户栈和偏移量即可获得发送的数据信息。

​	使用Cilium/ebpf库在Golang的HTTP server上添加Uretprobe，使用vmlinux.h替换cilium库默认自带的common.h头文件（需要拿到`pt_regs`的sp属性，要有完全的内核结构头文件）。结果运行探针时，**发现HTTP server会发生崩溃，或运行几次后再崩溃**。

<img src="https://cdn.nlark.com/yuque/0/2022/png/752866/1656421675372-a93b3882-3a77-4f72-8e07-b1e605a7a1ac.png?x-oss-process=image%2Fresize%2Cw_643%2Climit_0" alt="image.png" />

​	发现在这个[issue](https://github.com/iovisor/bcc/issues/1320)里也有人遇到了相同的问题。实际上如果程序没有奔溃也有可能出现程序带着脏数据执行，出现完全不可控的情况。

​	报错中出现的`SIGILL`信号代表CPU 执行了一个它并不理解的指令或者是寄存器跳到了一个非法的地址了。指令就是这段`instruction bytes: 0x0 0x0 0x0 0x0 0x0...`

<img src="https://cdn.nlark.com/yuque/0/2022/png/752866/1656422475467-0aabecd1-12f1-430a-8392-ab46ac3c13d8.png?x-oss-process=image%2Fresize%2Cw_760%2Climit_0" alt="image.png" />

​	官方解释如下：Golang 进程在 GC 和调度的时候是栈地址是会变化的，而 BPF 在使用 uretporbe 的时候需要提前指定好符号表中的栈地址，这时候就会导致进程奔溃了，应该是上面讲的寄存器跳到了一个非法的地址。

<img src="https://cdn.nlark.com/yuque/0/2022/png/752866/1656422706742-0184d9cd-d552-4534-bfe7-c427e3eb6789.png?x-oss-process=image%2Fresize%2Cw_768%2Climit_0" alt="image.png"  />

​	通过查阅资料，最根本原因是是 **golang 特定的 goroutine 协程机制和连续栈生成分配方式**， 每个 goroutine 会有自己独立的 stack 空间，最开始的时候分配的大小为 2k， 但是如果 goroutine 的栈空间超过了 2k 这时 golang 程序会重新分配一个 4k 的栈空间，并且将之前 stack 上的数据 copy 到新的 stack 上。其次由于 **uretprobe 机制，会使用 trampoline 蹦床机制，通过 JMP 指令插入自定义逻辑， 但是最后需要 JMP 回原地址，结合 golang 的连续栈机制，如果 goroutine 在调用过程发生了栈扩容/收缩 会导致 JMP 回的原地址是错误的，**所以会导致 golang 程序崩溃或者不可遇知的错误。

#### 解决方法

​	虽然可以通过通过**Uprobe的方式扫描源程序 ELF 文件，找到函数的开始位置，在所有RET 指令位置注入 uprobe 探针，**这样可以模拟 uretprobe，但Cilium/ebpf库中并未有成熟的通过UprobeOffset方式添加uprobe符号偏移量，因此最后使用Kprobe完成HTTP数据的捕获。

#### **心得**

​	在开发过程中遇到问题时，需要及时搜索解决方法，而不是一个人自己闷头思考，因为有时候可能是编程语言、工具的固有缺陷。在stackoverflows上可以查到许多有效的方法，而在相关开源项目的Issue和PR中，也能发现一些正在解决中的问题。

### 2.开发规范问题

#### 2.1 对Map实现并发访问

使用多协程对同一个Map进行读写时，会出现`fatal error: concurrent map writes map`的错误提示。必须提供某种同步机制，一般情况下通过读写锁sync.RWMutex实现对map的并发访问控制，将map和sync.RWMutex封装一下，可以实现对map的安全并发访问。

```GO
type PerStatusWithLock struct {
	sync.RWMutex
	perStatus map[time.Time][]perTimeStatus
}
func (m *PerStatusWithLock) addPerMap(t time.Time, s perTimeStatus) {
	m.Lock()
	m.perStatus[t] = append(m.perStatus[t], s) //each timestamp add the resp(including statusCode\len)
	m.Unlock()
}
func (m *PerStatusWithLock) readPerMap() map[time.Time][]perTimeStatus {
	m.RLock()
	rmap := m.perStatus
	m.RUnlock()
	return rmap
}
```

#### 2.2 BPF堆栈尺寸限制

想要将uprobe程序里的数据组装为一个event一次性PERF OUT，于是声明了一个较大的struct，结果报错`Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map`

因此声明了PERCPU_ARRAY，每一次循环使用ARRAY里的数组。因为是循环使用，所以每一次都要进行合理的初始化定义。

```C
struct operator_header_t{
    struct go_grpc_http2_header_event_t event[8];
    int64_t ns;
};
BPF_PERCPU_ARRAY(operator_header_heap,struct operator_header_t,1);

//in function
struct operator_header_t *e=operator_header_heap.lookup(&zero);
if (e==NULL){
    bpf_trace_printk("return");
    return;}
e->ns=bpf_ktime_get_ns();
...
operator_header_events.perf_submit(ctx, e, sizeof(*e));
```

#### **心得**

​	在进行开发前，应尽量多的对当前的编程方法、流程等“优雅”的规范有所学习，以避免知识点的遗漏而导致的程序错误问题。可以先大致浏览，在开发过程中再进行实战。

### 3.Golang ABI调用问题

​	在Golang1.18的环境下开发，此版本下Golang 已更换为基于寄存器传参的调用规约。通过bcc的`PT_REGS_PARAM(ctx->di、si)等`尝试了x86-64架构下的通用寄存器惯例也不太匹配，导致的问题是在通过uprobe获取函数参数时，函数入参、返回值的顺序与通用平台ABI有差别，数据错乱。

#### 解决方法

​	通过查阅官方文档和资料，编写了简单的Golang传参函数，编译后查看其汇编代码。通过汇编代码，可以看到Golang最多支持9个参数的寄存器传递，按照AX、BX、CX、DI、SI、R8、R9、R10、R11的顺序，而多余的参数则存入栈中。返回值同样按照此顺序进行参数传递，多余的返回值存入栈中。并且在Go中，所有的寄存器都是Caller saved，在被调用者中也就是子函数中，返回值直接覆盖入参使用的寄存器。

```C
package main

import "fmt"

//go:noinline
func regsfunc(a int, b int, c int, d int, e int, f int, g int, h int, i int, j int, k int) (int, int, int, int, int, int, int, int, int, int, int) {
	return a + 1, a + 2, a + 3, a + 4, a + 5, a + 6, a + 7, a + 8, a + 9, a + 10, a + 11
}
func main() {
	fmt.Println(regsfunc(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11))
}
//go tool compile -S
0x0004 00004 (main.go:7)	MOVQ	DX, "".~r9+24(SP)
0x0009 00009 (main.go:7)	LEAQ	11(AX), DX
0x000d 00013 (main.go:7)	MOVQ	DX, "".~r10+32(SP)
0x0012 00018 (main.go:7)	LEAQ	1(AX), DX
0x0016 00022 (main.go:7)	LEAQ	2(AX), BX
0x001a 00026 (main.go:7)	LEAQ	3(AX), CX
0x001e 00030 (main.go:7)	LEAQ	4(AX), DI
0x0022 00034 (main.go:7)	LEAQ	5(AX), SI
0x0026 00038 (main.go:7)	LEAQ	6(AX), R8
0x002a 00042 (main.go:7)	LEAQ	7(AX), R9
0x002e 00046 (main.go:7)	LEAQ	8(AX), R10
0x0032 00050 (main.go:7)	LEAQ	9(AX), R11
0x0036 00054 (main.go:7)	MOVQ	DX, AX
```

#### 心得

​	在开发过程中，计算机组成原理是经常绕不开的一个主题，需要对底层知识有所了解，在debug过程中起码能够有寻找的方向。

## 项目完成质量

​	在完成本项目过程中，参考、查阅了许多已有的云监控方案，观察到对于云监控领域中，对于应用层的协议非侵入捕获尚不成熟，因此尝试使用eBPF技术进行开发创新，将内核中的eBPF和集群中的应用业务层数据进行结合，进行交叉，存在一定的创新性。

​	在开发框架上，使用了Golang语言，以Gobpf作为主体开发技术，将HTTP协议、gRPC协议常见指标进行捕获和建模，并对接成熟的可视化组件Prometheus，完成度较高。

​	目前尚未实现CO-RE等BPF前沿技术，且本项目尚未能直接投入生产环境直接使用，有待后续继续开发。

## 与导师及反馈情况

​	与导师联系紧密，遇到问题及时咨询，并有每周例会辅助开发汇报及总结指示。