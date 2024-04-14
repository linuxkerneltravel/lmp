## iptables

iptables是使 用很广泛的防火墙工具之一，它基于内核的包过滤框架 netfilter。

### iptables工作流程
iptables是采用数据包过滤机制工作的，所以它会对请求的数据包的包头进行分析，并根据我们预先设定的规则进行匹配来决定是否可以进入主机。并且

① 防火墙是一层一层过滤的。实际是按照配置规则的顺序从上到下，从前到后进行过滤的；
② 如果匹配上规则，即明确表明阻止还是通过，此时数据包就不再向下匹配新规则了；
③ 如果所有规则中没有明确表明是阻止还是通过这个数据包，也就是没有匹配上规则，则按照默认策略进行处理；
④ 防火墙的默认规则是对应的链的所有的规则执行完成后才会执行的；

### iptables四表五链

#### 表与链的对应关系

| 表      | 链          | 说明                                                     |
| ------- | ----------- | -------------------------------------------------------- |
| Filter  | INPUT       | 对于指定到本地套接字的包，即到达本地防火墙服务器的数据包 |
| Filter  | FORWARD     | 路由穿过的数据包，即经过本地防火墙服务器的数据包         |
| Filter  | OUTPUT      | 本地创建的数据包                                         |
| NAT     | PREROUTING  | 一进来就对数据包进行改变                                 |
| NAT     | OUTPUT      | 本地创建的数据包在路由之前进行改变                       |
| NAT     | POSTROUTING | 在数据包即将出去时改变数据包信息                         |
| Managle | INPUT       | 进入到设备本身的包                                       |
| Managle | FORWARD     | 对路由后的数据包信息进行修改                             |
| Managle | PREROUTING  | 在路由之前更改传入的包                                   |
| Managle | OUTPUT      | 本地创建的数据包在路由之前进行改变                       |
| Managle | POSTROUTING | 在数据包即将离开时更改数据包信息                     

其中，Filter表为默认表、NAT表为当遇到新创建的数据包连接时参考、Managle表专门用于改变数据包。

规则链名包括(也被称为五个钩子函数)：

- INPUT链 ：处理输入数据包。
- OUTPUT链 ：处理输出数据包。
- FORWARD链 ：处理转发数据包。
- PREROUTING链 ：用于目标地址转换(DNAT)。
- POSTOUTING链 ：用于源地址转换(SNAT)。

#### 作用

| filter表 |                                        |
| -------- | -------------------------------------- |
| INPUT    | 负责过滤所有目标地址是本机地址的数据包 |
| FORWARD  | 负责转发流经主机的数据包               |
| OUTPUT   | 处理所有本机地址的数据包               |

| filter表    |                                                              |
| ----------- | ------------------------------------------------------------ |
| OUTPUT      | 改变主机发出数据包的目标地址                                 |
| PREROUTING  | 在数据包到达防火墙时，进行路由判断之前执行的规则，作用是改变数据包的目标地址、目的端口等 |
| POSTROUTING | 在数据包离开防火墙时进行路由判断之后的规则，作用是改变数据包的源地址、源端口等 |


### iptables原理

iptables 与协议栈内有包过滤功能的 hook 交 互来完成工作。这些内核 hook 构成了 netfilter 框架。

每个进入网络系统的包（接收或发送）在经过协议栈时都会触发这些 hook，程序可以通过注册 hook 函数的方式在一些关键路径上处理网络流量。iptables 相关的内核模块在这些 hook 点注册了处理函数，因此可以通过配置 iptables 规则来使得网络流量符合防火墙规则。

netfilter 提供了 5 个 hook 点。包经过协议栈时会触发**内核模块注册在这里的处理函数** 。触发哪个 hook 取决于包的方向（是发送还是接收）、包的目的地址、以及包在上一个 hook 点是被丢弃还是拒绝等等。

下面几个 hook 是内核协议栈中已经定义好的：

- `NF_IP_PRE_ROUTING`: 接收到的包进入协议栈后立即触发此 hook，在进行任何路由判断 （将包发往哪里）之前
- `NF_IP_LOCAL_IN`: 接收到的包经过路由判断，如果目的是本机，将触发此 hook
- `NF_IP_FORWARD`: 接收到的包经过路由判断，如果目的是其他机器，将触发此 hook
- `NF_IP_LOCAL_OUT`: 本机产生的准备发送的包，在进入协议栈后立即触发此 hook
- `NF_IP_POST_ROUTING`: 本机产生的准备发送的包或者转发的包，在经过路由判断之后， 将触发此 hook

iptables 使用表来组织规则，根据用来做什么类型的判断标准，将规则分为不同表。在每个表内部，规则被进一步组织成链，内置的 链 是由内置的hook触发的。链基本上能决定规则何时被匹配。

内置的链名字和 netfilter hook 名字是一一对应的：

- `PREROUTING`: 由 `NF_IP_PRE_ROUTING` hook 触发
- `INPUT`: 由 `NF_IP_LOCAL_IN` hook 触发
- `FORWARD`: 由 `NF_IP_FORWARD` hook 触发
- `OUTPUT`: 由 `NF_IP_LOCAL_OUT` hook 触发
- `POSTROUTING`: 由 `NF_IP_POST_ROUTING` hook 触发

链使管理员可以控制在包的传输路径上哪个点应用策略。因为每个表有多个链，因此一个表可以在处理过程中的多 个地方施加影响。特定类型的规则只在协议栈的特定点有意义，因此并不是每个表都 会在内核的每个 hook 注册链。

<img src="./images/arch.png">

<img src="./images/overview.png">

Ref

https://arthurchiao.art/blog/deep-dive-into-iptables-and-netfilter-arch-zh/

https://mp.weixin.qq.com/s/ZyZ_VpsewX5b2E-fwtGgsg