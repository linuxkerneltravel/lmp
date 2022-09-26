### XDP Fast Forward

XDP 在路由方面有着先天的优势，可以在驱动层（native模式）进行转发，不需要进入内核网络协议栈以降低开销。

#### 思路

eBPF Helpers函数中，`bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int
       plen, u32 flags)`
具有查询内核路由表的能力，可以根据传入的`params`进行查询，并返回下一跳。之后再使用另一个 Helpers 函数`bpf_redirect`即可进行转发到指定的网卡。

每次使用`bpf_fib_lookup`进行查询开销依然会很大，所以可以在BPF MAP中维护一张表，用来缓存查询到的结果，下一次查询时就可以直接从该表中读取，无需再通过内核网络协议栈查找，从而进一步提升转发速度。

#### 验证

使用 KVM 创建三台虚拟机，分别为Host 1、Host 2、Host 3。并创建两个桥接网络，分别为 br1 、br2。Host 1添加两张网卡，分别连接 br1 、br2。Host 2、Host 3分别添加一张网卡，并分别连接 br1 、 br2（网卡类型均为 virtio ）。在Host 2、Host 3上分别添加静态路由 `route add default gw`，网关地址设为Host 1所对应的地址。在 Host 1 上启动 XDP 程序，分别挂在到两个网卡上。在 Host 2 启动 iperf 服务器端程序，并在 Host 3 上启动 iperf 客户端程序，进行测试。初步实验得到的结果是，使用 XDP 进行转发性能略有提升，但差距很小。