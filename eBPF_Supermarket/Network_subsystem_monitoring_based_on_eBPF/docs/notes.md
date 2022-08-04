# 开发过程之问题与解决方案

1. bcc获取events数据并解析（tcpconnection.py）

在Python代码的print_ipv6_event函数中，tcp连接的相关信息获取如下
``` Python
event = b["ipv6_events"].event(data)
```
此时由bcc将C中的结构体解析成Python中的变量，若不单独指定转换方法，转换过程将由bcc完成。如下结构体的转换将会出错：

``` C
struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u8 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u8 direction;
    char task[TASK_COMM_LEN];
};
```
原因在于：结构体存在多种对齐方式的成员，例如128位int，偏移量不按照32位对齐时，bcc结构体解析可能会出错。
而调整其中变量顺序如下，或使结构体成员变量均按照32位对齐，则可以避免转换出错的问题：
``` C
struct ipv6_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u8 ip;
    u16 sport;
    u16 dport;
    u8 direction;
    char task[TASK_COMM_LEN];
};
```

2. 程序运行出现Exception: Failed to load BPF program b'xxx': Permission denied

[相关issue](https://github.com/iovisor/bcc/issues/3190)

```
This is a btf issue. Currently the rewriter is not intelligent enough to understand PT_REGS_PARM2, so it won't transform how->flags to proper bpf_probe_read. 
```
原本的程序为
```C
u16 sport = skp->__sk_common.skc_num;
u16 dport = skp->__sk_common.skc_dport;
// ...
```
由于bcc没有那么聪明，不能总能够自动生成bpf_probe_read_kernel，让用户直接读结构体的成员，因此程序应改成如下：
```C
bpf_probe_read_kernel(&data4.saddr, sizeof(data4.saddr),
    &skp->__sk_common.skc_rcv_saddr);
bpf_probe_read_kernel(&data4.daddr, sizeof(data4.daddr),
    &skp->__sk_common.skc_daddr);
// ...
```
