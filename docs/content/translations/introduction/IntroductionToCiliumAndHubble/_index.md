+++
title = "Introduction to Cilium & Hubble"
description = "对 Cilium & Hubble 的介绍"
weight = 5

+++

[原文链接](https://docs.cilium.io/en/stable/intro/)

## Introduction to Cilium & Hubble

## 对 Cilium & Hubble 的介绍

### What is Cilium?
Cilium is open source software for transparently securing the network connectivity between application services deployed using Linux container management platforms like Docker and Kubernetes.

### 什么是Cilium？
Cilium 是开源软件，用于透明地保护使用 Linux 容器管理平台（如 Docker 和 Kubernetes ）部署的应用程序服务之间的网络连接。

At the foundation of Cilium is a new Linux kernel technology called eBPF, which enables the dynamic insertion of powerful security visibility and control logic within Linux itself. Because eBPF runs inside the Linux kernel, Cilium security policies can be applied and updated without any changes to the application code or container configuration.

Cilium 的基础是一种名为 eBPF 的新 Linux 内核技术，它能够在 Linux 本身内动态插入强大的安全可视性和控制逻辑。 由于 eBPF 在 Linux 内核中运行，因此应用和更新 Cilium 安全策略无需对应用程序代码或容器配置进行任何更改。 
### What is Hubble?
Hubble is a fully distributed networking and security observability platform. It is built on top of Cilium and eBPF to enable deep visibility into the communication and behavior of services as well as the networking infrastructure in a completely transparent manner.

### 什么是Hubble？

Hubble 是一个完全分布式的网络和安全可观测性平台。 它建立在 Cilium 和 eBPF 之上，能够以完全透明的方式深入了解服务以及网络基础设施的通信和行为。

By building on top of Cilium, Hubble can leverage eBPF for visibility. By relying on eBPF, all visibility is programmable and allows for a dynamic approach that minimizes overhead while providing deep and detailed visibility as required by users. Hubble has been created and specifically designed to make best use of these new eBPF powers.

通过在 Cilium 之上构建，Hubble 可以提高 eBPF 的可视性。通过依赖于 eBPF ，所有可视性都是可编程的，并且允许采用动态方法来最大限度地减少开销，同时根据用户的要求提供深入和详细的可视性。 Hubble 是为了充分利用这些新的 eBPF 能力而创立和专门设计的。

Hubble can answer questions such as:

Hubble可以回答以下问题：

#### Service dependencies & communication map
- What services are communicating with each other? How frequently? What does the service dependency graph look like?
- What HTTP calls are being made? What Kafka topics does a service consume from or produce to?

#### 服务依赖&通信图谱
- 哪些服务之间相互通信？有多频繁？服务依赖关系图是什么样的？
- 正在建立哪些 HTTP  Calls？一项服务使用或产生什么 Kafka topics？

#### Network monitoring & alerting
- Is any network communication failing? Why is communication failing? Is it DNS? Is it an application or network problem? Is the communication broken on layer 4 (TCP) or layer 7 (HTTP)?
- Which services have experienced a DNS resolution problem in the last 5 minutes? Which services have experienced an interrupted TCP connection recently or have seen connections timing out? What is the rate of unanswered TCP SYN requests?

#### 网络监控&警报
- 是否有网络通信失败？为什么通信失败？是 DNS 吗？是应用程序问题还是网络问题？是第4层（TCP）还是第7层（HTTP）上的通信中断？
- 哪些服务在过去5分钟内遇到了DNS解析问题？哪些服务最近遇到了 TCP 连接中断或连接超时？未响应的 TCP SYN 请求的比例是多少？

#### Application monitoring
- What is the rate of 5xx or 4xx HTTP response codes for a particular service or across all clusters?
- What is the 95th and 99th percentile latency between HTTP requests and responses in my cluster? Which services are performing the worst? What is the latency between two services?

#### 应用监控
- 特定服务或所有集群中5xx或4xx的 HTTP 响应代码比例是多少？
- 在我的集群中 HTTP 请求和响应的第95个和第99个百分位延迟（P95 latency 和 P99 latency）是多少？哪些服务表现最差？两个服务之间的延迟是多少？

#### Security observability
- Which services had connections blocked due to network policy? What services have been accessed from outside the cluster? Which services have resolved a particular DNS name?

#### 安全可观测性
- 由于网络策略，哪些服务的连接被阻止了？从集群外部访问了哪些服务？哪些服务解析了特定的 DNS 名称？

### Why Cilium & Hubble?
eBPF is enabling visibility into and control over systems and applications at a granularity and efficiency that was not possible before. It does so in a completely transparent way, without requiring the application to change in any way. eBPF is equally well-equipped to handle modern containerized workloads as well as more traditional workloads such as virtual machines and standard Linux processes.

### 为什么是Cilium & Hubble？
eBPF 正在以以前不可能的粒度和效率实现对系统和应用程序的可视性和控制。它以一种完全透明的方式执行，不需要应用程序进行任何更改。eBPF 同样具备处理现代容器化工作负载以及更传统的工作负载（如虚拟机和标准 Linux 进程）的能力。 

The development of modern datacenter applications has shifted to a service-oriented architecture often referred to as microservices, wherein a large application is split into small independent services that communicate with each other via APIs using lightweight protocols like HTTP. Microservices applications tend to be highly dynamic, with individual containers getting started or destroyed as the application scales out / in to adapt to load changes and during rolling updates that are deployed as part of continuous delivery.

现代化数据中心应用程序的开发已经转向面向服务的架构，通常称为微服务，其中大型应用程序被拆分为小型独立服务，这些服务通过使用 HTTP 等轻量级协议的 API 相互通信。应用程序向外扩展或向内扩展以适应负载变化，以及在作为持续交付的一部分部署的滚动更新期间，通过单个容器的启动或销毁，微服务应用程序往往是高度动态的。

This shift toward highly dynamic microservices presents both a challenge and an opportunity in terms of securing connectivity between microservices. Traditional Linux network security approaches (e.g., iptables) filter on IP address and TCP/UDP ports, but IP addresses frequently churn in dynamic microservices environments. The highly volatile life cycle of containers causes these approaches to struggle to scale side by side with the application as load balancing tables and access control lists carrying hundreds of thousands of rules that need to be updated with a continuously growing frequency. Protocol ports (e.g. TCP port 80 for HTTP traffic) can no longer be used to differentiate between application traffic for security purposes as the port is utilized for a wide range of messages across services.

这种向高度动态微服务的转变在确保微服务之间的连接性方面既是挑战也是机遇。 传统的 Linux 网络安全方法（例如 iptables）过滤 IP 地址和 TCP/UDP 端口，但 IP 地址在动态微服务环境中频繁变动。 容器的高度不稳定的生命周期导致这些方法难以与应用程序并行扩展，因为负载平衡表和访问控制列表承载了需要以不断增长的频率更新的数十万条规则。 出于安全目的，协议端口（例如用于 HTTP 流量的 TCP 端口 80）不再用于区分应用程序流量，因为该端口用于跨服务的各种消息。 

An additional challenge is the ability to provide accurate visibility as traditional systems are using IP addresses as primary identification vehicle which may have a drastically reduced lifetime of just a few seconds in microservices architectures.

另一个挑战是提供准确可视性的能力，因为传统系统使用 IP 地址作为主要识别工具，这在微服务架构中可能会大幅缩短生命周期，仅为几秒钟。 

By leveraging Linux eBPF, Cilium retains the ability to transparently insert security visibility + enforcement, but does so in a way that is based on service / pod / container identity (in contrast to IP address identification in traditional systems) and can filter on application-layer (e.g. HTTP). As a result, Cilium not only makes it simple to apply security policies in a highly dynamic environment by decoupling security from addressing, but can also provide stronger security isolation by operating at the HTTP-layer in addition to providing traditional Layer 3 and Layer 4 segmentation.

通过利用 Linux eBPF，Cilium 保留了透明地插入安全可见性 + 强制执行的能力，但这样做的方式是基于服务/pod/容器身份（与传统系统中的 IP 地址标识相反）并且可以过滤应用程序层（例如 HTTP）。 因此，Cilium 不仅通过将安全与寻址解耦，使在高度动态的环境中应用安全策略变得简单，而且除了提供传统的第 3 层和第 4 层分段之外，还可以通过在 HTTP 层运行来提供更强的安全隔离 。

The use of eBPF enables Cilium to achieve all of this in a way that is highly scalable even for large-scale environments.

eBPF 的使用使 Cilium 能够以高度可扩展的方式实现所有这些，即使对于大规模环境也是如此。 

### Functionality Overview

### 功能概述

#### Protect and secure APIs transparently
Ability to secure modern application protocols such as REST/HTTP, gRPC and Kafka. Traditional firewalls operates at Layer 3 and 4. A protocol running on a particular port is either completely trusted or blocked entirely. Cilium provides the ability to filter on individual application protocol requests such as:

#### 透明地保护和使API安全

能够保护现代应用程序协议，例如 REST/HTTP、gRPC 和 Kafka。 传统防火墙在第 3 层和第 4 层运行。在特定端口上运行的协议要么完全受信任，要么完全被阻止。 Cilium 提供了过滤单个应用程序协议请求的能力，例如： 

- Allow all HTTP requests with method `GET` and path `/public/.*`. Deny all other requests.

- Allow `service1` to produce on Kafka topic `topic1` and `service2` to consume on `topic1`. Reject all other Kafka messages.

- Require the HTTP header `X-Token: [0-9]+` to be present in all REST calls.

- 允许使用`GET`方法 和路径 `/public/.*` 的所有 HTTP 请求。 拒绝所有其他请求。

- 允许 `service1` 在 Kafka 主题 `topic1` 上生产，而 `service2` 在 `topic1` 上消费。 拒绝所有其他 Kafka 消息。

- 要求 HTTP 标头 `X-Token: [0-9]+` 出现在所有 REST 调用中。 

See the section [Layer 7 Policy](http://docs.cilium.io/en/stable/policy/#layer-7) in our documentation for the latest list of supported protocols and examples on how to use it.

请参阅我们文档中的第 7 层策略部分( [Layer 7 Policy](http://docs.cilium.io/en/stable/policy/#layer-7) )，以获取支持的协议的最新列表以及有关如何使用它的示例。 

#### Secure service to service communication based on identities

#### 基于身份的安全服务到服务通信 

Modern distributed applications rely on technologies such as application containers to facilitate agility in deployment and scale out on demand. This results in a large number of application containers to be started in a short period of time. Typical container firewalls secure workloads by filtering on source IP addresses and destination ports. This concept requires the firewalls on all servers to be manipulated whenever a container is started anywhere in the cluster.

现代分布式应用程序依赖于应用程序容器等技术来促进部署的敏捷性和按需扩展。 这导致在短时间内启动大量应用程序容器。 典型的容器防火墙通过过滤源 IP 地址和目标端口来保护工作负载。 这个概念要求每当容器在集群中的任何地方启动时，所有服务器上的防火墙都可以被操作。 

In order to avoid this situation which limits scale, Cilium assigns a security identity to groups of application containers which share identical security policies. The identity is then associated with all network packets emitted by the application containers, allowing to validate the identity at the receiving node. Security identity management is performed using a key-value store.

为了避免这种限制规模的情况，Cilium 将安全身份分配给共享相同安全策略的应用程序容器组。 然后，该身份与应用程序容器发出的所有网络数据包相关联，从而允许在接收节点验证身份。 使用键值存储执行安全身份管理。 

#### Secure access to and from external services

#### 安全地访问外部服务

Label based security is the tool of choice for cluster internal access control. In order to secure access to and from external services, traditional CIDR based security policies for both ingress and egress are supported. This allows to limit access to and from application containers to particular IP ranges.

基于标签的安全性是集群内部访问控制的首选工具。基于标签的安全性是集群内部访问控制的首选工具。 为了保护对外部服务的访问，支持传统的基于 CIDR 的入口和出口安全策略。 这允许限制对应用程序容器的访问和来自特定 IP 范围的访问。 

#### Simple Networking

A simple flat Layer 3 network with the ability to span multiple clusters connects all application containers. IP allocation is kept simple by using host scope allocators. This means that each host can allocate IPs without any coordination between hosts.

The following multi node networking models are supported:

#### 简单网络

一个能够跨越多个集群的简单平坦的第三层网络连接所有应用程序容器。通过使用主机作用域分配器，可以使IP分配保持简单。这意味着每个主机都可以分配IP，而不需要主机之间进行任何协调。

支持以下多节点网络模型：

- **Overlay:**Encapsulation-based virtual network spanning all hosts. Currently VXLAN and Geneve are baked in but all encapsulation formats supported by Linux can be enabled.

- **Overlay:**覆盖所有主机的基于封装的虚拟网络。 目前 VXLAN 和 Geneve 已内置，但 Linux 支持的所有封装格式都可以启用。

​        When to use this mode: This mode has minimal infrastructure and integration requirements. It works on almost any network   infrastructure as the only requirement is IP connectivity between hosts which is typically already given.

​	何时使用此模式：此模式对基础架构和集成的要求最低。 它几乎适用于任何网络基础设施，因为唯一的要求是通常已经给出的主机之间的 IP 连接。

- **Native Routing: **Use of the regular routing table of the Linux host. The network is required to be capable to route the IP addresses of the application containers.

- **Native Routing: **使用 Linux 主机的常规路由表。 网络需要能够路由应用程序容器的 IP 地址。 

​        When to use this mode: This mode is for advanced users and requires some awareness of the underlying networking infrastructure. This mode works well with:
​        · Native IPv6 networks
​        · In conjunction with cloud network routers
​        · If you are already running routing daemons

​        何时使用此模式：此模式适用于高级用户，需要对底层网络基础设施有所了解。 此模式适用于：
​        · 原生 IPv6 网络
​        · 配合云网路路由器
​        · 如果你已经在运行路由守护进程 

#### Load Balancing
Cilium implements distributed load balancing for traffic between application containers and to external services and is able to fully replace components such as kube-proxy. The load balancing is implemented in eBPF using efficient hashtables allowing for almost unlimited scale.

#### 负载均衡

Cilium 为应用程序容器和外部服务之间的流量实现分布式负载平衡，并且能够完全替换 kube-proxy 等组件。 负载平衡是在 eBPF 中使用高效的哈希表实现的，允许几乎无限的规模。 

For north-south type load balancing, Cilium’s eBPF implementation is optimized for maximum performance, can be attached to XDP (eXpress Data Path), and supports direct server return (DSR) as well as Maglev consistent hashing if the load balancing operation is not performed on the source host.

对于南北向类型的负载均衡（north-south type load balancing），Cilium 的 eBPF 实现针对最大性能进行了优化，可以附加到 XDP（eXpress Data Path），并且支持直接服务器返回 (DSR) 以及在源主机上不执行负载均衡操作的情况下支持 Maglev 一致性哈希。 

For east-west type load balancing, Cilium performs efficient service-to-backend translation right in the Linux kernel’s socket layer (e.g. at TCP connect time) such that per-packet NAT operations overhead can be avoided in lower layers.

对于东西向类型的负载平衡（east-west type load balancing），Cilium 在 Linux 内核的套接字层（例如在 TCP 连接时）执行高效的服务到后端转换，这样可以避免较低层中的每个数据包 NAT 操作开销。 

#### Bandwidth Management
Cilium implements bandwidth management through efficient EDT-based (Earliest Departure Time) rate-limiting with eBPF for container traffic that is egressing a node. This allows to significantly reduce transmission tail latencies for applications and to avoid locking under multi-queue NICs compared to traditional approaches such as HTB (Hierarchy Token Bucket) or TBF (Token Bucket Filter) as used in the bandwidth CNI plugin, for example.

#### 带宽管理

Cilium 通过基于 EDT（Earliest Departure Time）的高效的速率限制和 eBPF 来实现带宽管理出口节点的容器流量。 例如，与带宽 CNI 插件中使用的 HTB（Hierarchy Token Bucket）或 TBF（Token Bucket Filter）等传统方法相比，这可以显著减少应用程序的传输尾延迟，并避免在多队列 NIC 下锁定。 

#### Monitoring and Troubleshooting
The ability to gain visibility and to troubleshoot issues is fundamental to the operation of any distributed system. While we learned to love tools like `tcpdump` and `ping` and while they will always find a special place in our hearts, we strive to provide better tooling for troubleshooting. This includes tooling to provide:

监控和故障排查

获得可视性和解决问题的能力是任何分布式系统运行的基础。虽然我们喜欢使用如`tcpdump`和`ping`这样的工具尽管它们在我们心中有着特殊的地位，我们仍努力为故障排除提供更好的工具。

- Event monitoring with metadata: When a packet is dropped, the tool doesn’t just report the source and destination IP of the packet, the tool provides the full label information of both the sender and receiver among a lot of other information.
- 使用元数据进行事件监控：当数据包被丢弃时，该工具不仅报告数据包的源和目标IP，还提供发送方和接收方的完整标签信息以及许多其他信息。
- Metrics export via Prometheus: Key metrics are exported via Prometheus for integration with your existing dashboards.
- 通过Prometheus导出指标：通过Prometheus导出关键指标，以便与现有仪表板集成。
- [Hubble](https://github.com/cilium/hubble/): An observability platform specifically written for Cilium. It provides service dependency maps, operational monitoring and alerting, and application and security visibility based on flow logs.
- [Hubble](https://github.com/cilium/hubble/): 专为 Cilium 编写的可观察性平台。 它提供基于流日志的服务依赖关系图、操作监控和警报以及应用程序和安全可见性。 