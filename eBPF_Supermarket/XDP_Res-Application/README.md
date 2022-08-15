## 基于 eBPF 的 XDP 研究与应用

XDP 提供了一个内核态下高性能的可编程包处理框架，可在最早可以处理包的位置（即网卡驱动收到包的时刻）运行 BPF 程序，其具有非常优秀的数据面处理性能，打通了 Linux 网络处理的高速公路。本题目要求基于eBPF 和 XDP 进行研究，完成的内容包括：（1）分析 eBPF XDP实现的基本原理。（2）对比 XDP 和其它 Kernel Bypass 方案的优缺点，找出其适合的应用场景。（3）针对该应用场景进行编程设计，并可达到性能提升或安全性提升的效果。（4）可能的情况下，尝试将该工具部署在华为的鸿蒙系统上并进行测试。（加分项）

### XDP基本原理

XDP 可在最早可以处理包的位置（即网卡驱动收到包的时刻）运行 BPF 程序，并且暴露了一个可以加载 BPF 程序的网络钩子。在这个钩子中，程序能够对传入的数据包进行判别修改并快速决策，避免了内核内部处理带来的额外开销。
XDP 程序运行在内核网络协议栈之前，一个数据包经过网络协议栈的处理会产生相当大的开销，所以 XDP 提供了几种基本的能力，包括：

- XDP_DROP

丢弃且不处理数据包。eBPF 程序可以分析流量模式并使用过滤器实时更新 XDP 应用程序以丢弃特定类型的数据包（例如，恶意流量）。

- XDP_PASS

指示应将数据包转发到正常网络堆栈以进行进一步处理。XDP 程序可以在此之前修改包的内容。

- XDP_TX

将数据包（可能已被修改）转发到接收它的同一网络接口。

- XDP_REDIRECT

绕过正常的网络堆栈并通过另一个 NIC 将数据包重定向到网络。

关于XDP的其它内容，可以参考`./docs/xdp`目录其它文档：

XDP与题目应用背景：[backgroup.md](./docs/xdp/backgroud.md)

XDP基础内容：[xdp_basic.md](./docs/xdp/xdp_basic.md)

XDP与Kernel Bypass方案对比：[compare.md](./docs/xdp/compare.md)


### XDP iptables

#### 背景

netfilter/iptables 是 Linux 中内置的防火墙，其可以根据指定规则进行包过滤、重定向等功能。但是随着网络吞吐量的高速增长，netfilter/iptables 存在着很大的性能瓶颈，导致服务出现不可预测的延迟和性能下降。netfilter 框架在 IP 层，报文需要经过链路层，IP 层才能被处理，如果是需要丢弃报文，会白白浪费很多资源，影响整体性能，并且 netfilter 框架是一种可自由添加策略规则专家系统，并没有对添加规则进行合并优化，随着规模的增大，逐条匹配的机制也会影响性能。

利用 XDP 可以代替 netfilter/iptables 实现部分包过滤、重定向功能。XDP 可在最早可以处理包的位置运行 BPF 程序，根据预先设置的策略执行相应的动作，避免进入网络协议栈产生不必要的开销，从而提高系统的性能。根据测算，利用 XDP 技术的丢包速率要比 iptables 高 4 倍左右[1]。并且，通过改造匹配策略，借助 BPF HASH MAP ，可以进一步提升性能。

#### netfilter/iptables介绍与实现机制

netfilter/iptables 是采用数据包过滤机制工作的，它会对请求的数据包的包头进行分析，并根据预先设定的规则进行匹配来决定是否可以进入主机。它是一层一层过滤的，按照配置规则的顺序从上到下，从前到后进行过滤。iptables/netfilter 使用表来组织规则，根据用来做什么类型的判断标准，将规则分为不同表。在每个表内部，规则被进一步组织成链，内置的链是由内置的 hook 触发的。链基本上能决定规则何时被匹配。netfilter 在内核协议栈的各个重要关卡埋下了五个钩子。每一个钩子都对应是一系列规则，以链表的形式存在，所以俗称五链。当网络包在协议栈中流转到这些关卡的时候，就会依次执行在这些钩子上注册的各种规则，进而实现对网络包的各种处理。

关于 netfilter/iptables 以及其四表五链的其它内容，可以参考`./docs/iptables_netfilter`目录：

netfilter/iptables 具体介绍：[basic.md](./docs/iptables_netfilter/basic.md)

netfilter/iptables 内核实现：[kernel_implement.md](./docs/iptables_netfilter/kernel_implement.md)

#### 使用XDP提取五元组信息

在接收到包之后，可以通过计算偏移量，对数据包逐层解析的方式获取到五元组信息（传输层协议、源ip地址、目的ip地址、源端口号、目的端口号）。

```c
//data为数据包头指针，data_end为数据包结束位置指针
void *data = (void *)(long)ctx->data;
void *data_end = (void *)(long)ctx->data_end;
//偏移量
int offset = 0;
//存储五元组信息
struct metainfo info;
//以太网头部
struct ethhdr *eth = (struct ethhdr *)data;
//ip头部
struct iphdr *ip;
//以太网头部偏移量
offset = sizeof(struct ethhdr);
//通过数据包头+偏移量的方式得到ip头部
ip = data + offset;
//从ip头部获取信息
info.ipproto = ip->protocol;//协议
info.saddr = ip->saddr;//源地址
info.daddr = ip->daddr;//目的地址
//再次计算偏移量
offset += sizeof(struct iphdr);
if(info.ipproto == IPPROTO_TCP){
    //tcp头部
    struct tcphdr *tcp = data + offset;
    offset += sizeof(struct tcphdr);
    if(data + offset > data_end)
        return XDP_DROP;
    //从tcp头部获取信息
    info.sport = tcp->source;//源端口
    info.dport = tcp->dest;//目的端口
   }
else if(info.ipproto == IPPROTO_UDP){
    //udp头部
    struct udphdr *udp = data + offset;
    offset += sizeof(struct udphdr);
    if(data + offset > data_end)
        return XDP_DROP;
    //从udp头部获取信息
    info.sport = udp->source;//源端口
    info.dport = udp->dest;//目的端口
}
```

#### 规则匹配

参考字节跳动的匹配方案[1]，实现了规则匹配。

```c
//存储各项规则的BPF HASH MAP
BPF_HASH(ipproto_map, u32, u32);
BPF_HASH(saddr_map, u32, u32);
BPF_HASH(daddr_map, u32, u32);
BPF_HASH(sport_map, u16, u32);
BPF_HASH(dport_map, u16, u32);
BPF_HASH(action_map,u32, u32);

static int match_rule(struct metainfo *info){
   int result_bit = 0;
   //查找对应规则
   int *ipproto_bit = ipproto_map.lookup(&info->ipproto);
   int *saddr_bit = saddr_map.lookup(&info->saddr);
   int *daddr_bit = daddr_map.lookup(&info->daddr);
   int *sport_bit = sport_map.lookup(&info->sport);
   int *dport_bit = dport_map.lookup(&info->dport);
   if(ipproto_bit != NULL){ //是否匹配到对应规则
      if(*ipproto_bit != 0){ //0代表没有
         if(result_bit == 0){ //result_bit为空时，使result_bit等于该项规则编号
            result_bit = *ipproto_bit;
         }
         else
            result_bit = result_bit & *ipproto_bit; //如果result_bit不为空，与该规则编号进行按位与运算。
      }
   }
   if(saddr_bit != NULL){
      if(*saddr_bit != 0){
         if(result_bit == 0)
            result_bit = *saddr_bit;
         else
            result_bit = result_bit & *saddr_bit;
      }
   }
   if(daddr_bit != NULL){ 
      if(*daddr_bit != 0){     
         if(result_bit == 0)
            result_bit = *daddr_bit;
         else
            result_bit = result_bit & *daddr_bit;
      }
   }
   if(sport_bit != NULL){
      if(*sport_bit != 0){
         if(result_bit == 0)
            result_bit = *sport_bit;
         else
            result_bit = result_bit & *sport_bit;
      }
   }
   if(dport_bit != NULL){
      if(*dport_bit != 0){
         if(result_bit == 0)
            result_bit = *dport_bit;
         else
            result_bit = result_bit & *dport_bit;
      }
   }
   if(result_bit == 0) //如果result_bit仍未空，说明没有匹配到规则，执行XDP_PASS（即什么都不做）
      return XDP_PASS;
   //执行到这说明匹配到了规则，进一步处理
   result_bit &= -result_bit; //得到优先级最高的规则编号，等价于 result_bit &= !result_bit + 1
   //从action表里查找对应动作
   int *action = action_map.lookup(&result_bit);
      if(action != NULL)
         return *action; //返回对应动作

   return XDP_PASS; //没有找到相应动作，返回XDP_PASS
}
```

该规则匹配方案仍然存在一些问题，在实际运行过程中出现误处理，仍在改进中。

#### 运行

```
cd src
sudo python3 ./filter.py
```

目前自定义规则部分仍在编写，现有程序的规则是写在`rules.py`里的。

### Ref

[1] [字节跳动技术团队 —— eBPF技术实践：高性能ACL](https://blog.csdn.net/ByteDanceTech/article/details/106632252)