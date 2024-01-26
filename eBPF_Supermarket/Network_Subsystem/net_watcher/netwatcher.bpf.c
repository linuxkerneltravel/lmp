// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: blown.away@qq.com
//
// tcpwatch libbpf 内核函数

#include "netwatcher.h"
#include "vmlinux.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

struct ktime_info {                // us time stamp info发送数据包
    unsigned long long qdisc_time; // tx包离开mac层时间戳
    unsigned long long mac_time;   // tx、rx包到达mac层时间戳
    unsigned long long ip_time;    // tx、rx包到达ip层时间戳
    // unsigned long long tcp_time;      // tx、rx包到达tcp层时间戳
    unsigned long long tran_time;        // tx、rx包到达传输层时间戳
    unsigned long long app_time;         // rx包离开tcp层时间戳
    void *sk;                            // 此包所属 socket套接字
    unsigned char data[MAX_HTTP_HEADER]; // 用户层数据
};

struct packet_tuple {
    unsigned __int128 saddr_v6; // ipv6 源地址
    unsigned __int128 daddr_v6; // ipv6 目的地址
    unsigned int saddr;         // 源地址
    unsigned int daddr;         // 目的地址
    unsigned short sport;       // 源端口号
    unsigned short dport;       // 目的端口号
    unsigned int seq;           // seq报文序号
    unsigned int ack;           // ack确认号
    unsigned int tran_flag;     // 1:tcp 2:udp
    unsigned int len;
};

// 操作BPF映射的一个辅助函数
static __always_inline void * //__always_inline强制内联
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
    void *val;
    long err;

    val = bpf_map_lookup_elem(map, key); // 在BPF映射中查找具有给定键的条目
    if (val)
        return val;
    // 此时没有对应key的value
    err = bpf_map_update_elem(map, key, init,
                              BPF_NOEXIST); // 向BPF映射中插入或更新一个条目
    if (err && err != -EEXIST)              // 插入失败
        return 0;

    return bpf_map_lookup_elem(map, key); // 返回对应value值
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_CONN 1000

// 存储每个packet_tuple包所对应的ktime_info时间戳
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN *MAX_PACKET);
    __type(key, struct packet_tuple);
    __type(value, struct ktime_info);
} timestamps SEC(".maps");

// 包相关信息通过此buffer提供给userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} udp_rb SEC(".maps");
// 存储每个tcp连接所对应的conn_t
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN);
    __type(key, struct sock *);
    __type(value, struct conn_t);
} conns_info SEC(".maps");

// 根据ptid存储sock指针，从而在上下文无sock的内核探测点获得sock
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN);
    __type(key, u64);
    __type(value, struct sock *);
} sock_stores SEC(".maps");

// 存储每个pid所对应的udp包
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN *MAX_PACKET);
    __type(key, int);
    __type(value, struct packet_tuple);
} pid_UDP SEC(".maps");

const volatile int filter_dport = 0;
const volatile int filter_sport = 0;
const volatile int all_conn = 0, err_packet = 0, extra_conn_info = 0,
                   layer_time = 0, http_info = 0, retrans_info = 0, udp_info;

/* help macro */

// 连接的目标端口是否匹配于filter_dport的值
#define FILTER_DPORT                                                           \
    if (filter_dport) {                                                        \
        if (conn.dport != filter_dport) {                                      \
            return 0;                                                          \
        }                                                                      \
    }
// 连接的源端口是否匹配于filter_sport的值
#define FILTER_SPORT                                                           \
    if (filter_sport) {                                                        \
        if (conn.sport != filter_sport) {                                      \
            return 0;                                                          \
        }                                                                      \
    }

// 初始化conn_t结构
/*
#define CONN_INIT
    struct conn_t conn = {0}; //声明一各conn_t结构,并初始化为0 conn.pid = ptid
>> 32;                           //将ptid的高32位赋给pid conn.ptid = ptid;
//初始化ptid u16 protocol = BPF_CORE_READ(sk, sk_protocol);   //读取协议字段 if
(protocol != IPPROTO_TCP)                     //检查其协议字段是否为IPPROTO_TCP
        return 0;
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm)); //获取当前进程名字
    conn.sock = sk;                                  //套接字指针sk
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);     //地址族字段
    __be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);    //目标端口字段
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);         //源端口字段
    conn.family = family;
    conn.sport = sport;
    conn.dport = __bpf_ntohs(dport);                  //字节序转换
    conn.init_timestamp = bpf_ktime_get_ns() / 1000;  //将当前时间戳(s)
*/
#define CONN_INIT                                                              \
    struct conn_t conn = {0};                                                  \
    conn.pid = ptid >> 32;                                                     \
    conn.ptid = ptid;                                                          \
    u16 protocol = BPF_CORE_READ(sk, sk_protocol);                             \
    if (protocol != IPPROTO_TCP)                                               \
        return 0;                                                              \
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));                       \
    conn.sock = sk;                                                            \
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);                    \
    __be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);                   \
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);                        \
    conn.family = family;                                                      \
    conn.sport = sport;                                                        \
    conn.dport = __bpf_ntohs(dport);                                           \
    conn.init_timestamp = bpf_ktime_get_ns() / 1000;
/*
初始化conn_t地址相关信息
#define CONN_ADD_ADDRESS
    if (family == AF_INET) {                                      //Internet IP
Protocol conn.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);//获取源地址
        conn.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);    //获取目的地址
    } else if (family == AF_INET6) {                              //IP version 6
        bpf_probe_read_kernel( //从sk中读取IPv6连接的源地址 &conn.saddr_v6,
//存放位置 sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32), //读取大小
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);   //读取位置
        bpf_probe_read_kernel( //从sk中读取IPv6连接的目的地址 &conn.daddr_v6,
            sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }
*/
#define CONN_ADD_ADDRESS                                                       \
    if (family == AF_INET) {                                                   \
        conn.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);             \
        conn.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);                 \
    } else if (family == AF_INET6) {                                           \
        bpf_probe_read_kernel(                                                 \
            &conn.saddr_v6,                                                    \
            sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),          \
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);                \
        bpf_probe_read_kernel(                                                 \
            &conn.daddr_v6,                                                    \
            sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),              \
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);                    \
    }
/*
初始化conn其余额外信息
#define CONN_ADD_EXTRA_INFO                                      //添加额外信息
    if (extra_conn_info) {
        struct tcp_sock *tp = (struct tcp_sock *)sk; //新建tcp_sock结构体
        conn->srtt = BPF_CORE_READ(tp, srtt_us);                 //平滑往返时间
        conn->duration = bpf_ktime_get_ns() / 1000 - conn->init_timestamp;  //
已连接建立时长 conn->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
//已确认的字节数 conn->bytes_received = BPF_CORE_READ(tp,
bytes_received);//已接收的字节数 conn->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
//拥塞窗口大小 conn->rcv_wnd = BPF_CORE_READ(tp, rcv_wnd); //接收窗口大小
        conn->snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);    //慢启动阈值
        conn->total_retrans = BPF_CORE_READ(tp, total_retrans);  //重传包数
        conn->sndbuf = BPF_CORE_READ(sk, sk_sndbuf); //发送缓冲区大小(byte)
        conn->sk_wmem_queued = BPF_CORE_READ(sk,
sk_wmem_queued);//已使用的发送缓冲区 conn->tcp_backlog = BPF_CORE_READ(sk,
sk_ack_backlog);   //backlog传入连接请求的当前最大排队队列大小
        conn->max_tcp_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);
//max_backlog传入连接请求的最大挂起队列大小
    }

*/
#define CONN_ADD_EXTRA_INFO                                                    \
    if (extra_conn_info) {                                                     \
        struct tcp_sock *tp = (struct tcp_sock *)sk;                           \
        conn->srtt = BPF_CORE_READ(tp, srtt_us);                               \
        conn->duration = bpf_ktime_get_ns() / 1000 - conn->init_timestamp;     \
        conn->bytes_acked = BPF_CORE_READ(tp, bytes_acked);                    \
        conn->bytes_received = BPF_CORE_READ(tp, bytes_received);              \
        conn->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);                          \
        conn->rcv_wnd = BPF_CORE_READ(tp, rcv_wnd);                            \
        conn->snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);                  \
        conn->total_retrans = BPF_CORE_READ(tp, total_retrans);                \
        conn->sndbuf = BPF_CORE_READ(sk, sk_sndbuf);                           \
        conn->sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);              \
        conn->tcp_backlog = BPF_CORE_READ(sk, sk_ack_backlog);                 \
        conn->max_tcp_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);         \
    }

#define CONN_INFO_TRANSFER tinfo->sk = conn->sock; // 将conn->sock赋给tinfo->sk

/*
初始化pack_t结构
#define PACKET_INIT_WITH_COMMON_INFO
    struct pack_t *packet;        //创建pack_t指针
    packet = bpf_ringbuf_reserve(&rb, sizeof(*packet), 0);
//为pack_t结构体分配内存空间 if (!packet) {                //分配失败 return 0;
    }
    packet->err = 0;             //err
    packet->sock = sk;           //socket 指针
    packet->ack = pkt_tuple.ack; //确认号
    packet->seq = pkt_tuple.seq; //序号
*/
#define PACKET_INIT_WITH_COMMON_INFO                                           \
    struct pack_t *packet;                                                     \
    packet = bpf_ringbuf_reserve(&rb, sizeof(*packet), 0);                     \
    if (!packet) {                                                             \
        return 0;                                                              \
    }                                                                          \
    packet->err = 0;                                                           \
    packet->sock = sk;                                                         \
    packet->ack = pkt_tuple.ack;                                               \
    packet->seq = pkt_tuple.seq;

/* help macro end */

/* help functions */
// 将struct sock类型的指针转化为struct tcp_sock类型的指针
static struct tcp_sock *tcp_sk(const struct sock *sk) {
    return (struct tcp_sock *)sk;
}
// 将struct sk_buff类型的指针转化为struct udphdr类型的指针
static struct udphdr *skb_to_udphdr(const struct sk_buff *skb) {
    return (struct udphdr *)((
        BPF_CORE_READ(skb, head) +              // 报文头部偏移
        BPF_CORE_READ(skb, transport_header))); // 传输层部分偏移
}
// 将struct sk_buff类型的指针转化为struct tcphdr类型的指针
static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb) {
    return (struct tcphdr *)((
        BPF_CORE_READ(skb, head) +              // 报文头部偏移
        BPF_CORE_READ(skb, transport_header))); // 传输层部分偏移
}
// 将struct sk_buff类型的指针转化为struct iphdr类型的指针
static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb) {
    return (struct iphdr *)(BPF_CORE_READ(skb, head) +
                            BPF_CORE_READ(skb, network_header));
}
// 将struct sk_buff类型的指针转化为struct ipv6hdr类型的指针
static inline struct ipv6hdr *skb_to_ipv6hdr(const struct sk_buff *skb) {
    return (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                              BPF_CORE_READ(skb, network_header));
}

// 初始化packet_tuple结构指针pkt_tuple
static void get_pkt_tuple(struct packet_tuple *pkt_tuple, struct iphdr *ip,
                          struct tcphdr *tcp) {
    pkt_tuple->saddr = BPF_CORE_READ(ip, saddr);
    pkt_tuple->daddr = BPF_CORE_READ(ip, daddr);
    u16 sport = BPF_CORE_READ(tcp, source);
    u16 dport = BPF_CORE_READ(tcp, dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    //__bpf_ntohs根据字节序来转化为真实值(16位) 网络传输中为大端序(即为真实值)
    pkt_tuple->dport = __bpf_ntohs(dport);
    u32 seq = BPF_CORE_READ(tcp, seq);
    u32 ack = BPF_CORE_READ(tcp, ack_seq);
    pkt_tuple->seq = __bpf_ntohl(seq);
    //__bpf_ntohls根据字节序来转化为真实值(32位)
    pkt_tuple->ack = __bpf_ntohl(ack);

    pkt_tuple->tran_flag = TCP; // tcp包
}
// 初始化packet_tuple结构指针pkt_tuple
static void get_udp_pkt_tuple(struct packet_tuple *pkt_tuple, struct iphdr *ip,
                              struct udphdr *udp) {
    pkt_tuple->saddr = BPF_CORE_READ(ip, saddr);
    pkt_tuple->daddr = BPF_CORE_READ(ip, daddr);
    u16 sport = BPF_CORE_READ(udp, source);
    u16 dport = BPF_CORE_READ(udp, dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    //__bpf_ntohs根据字节序来转化为真实值(16位) 网络传输中为大端序(即为真实值)
    pkt_tuple->dport = __bpf_ntohs(dport);
    pkt_tuple->seq = 0;
    pkt_tuple->ack = 0;
    pkt_tuple->tran_flag = UDP; // udp包
}

static void get_pkt_tuple_v6(struct packet_tuple *pkt_tuple,
                             struct ipv6hdr *ip6h, struct tcphdr *tcp) {
    bpf_probe_read_kernel(&pkt_tuple->saddr_v6, sizeof(pkt_tuple->saddr_v6),
                          &ip6h->saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&pkt_tuple->daddr_v6, sizeof(pkt_tuple->daddr_v6),
                          &ip6h->daddr.in6_u.u6_addr32);
    u16 sport = BPF_CORE_READ(tcp, source);
    u16 dport = BPF_CORE_READ(tcp, dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    pkt_tuple->dport = __bpf_ntohs(dport);
    u32 seq = BPF_CORE_READ(tcp, seq);
    u32 ack = BPF_CORE_READ(tcp, ack_seq);
    pkt_tuple->seq = __bpf_ntohl(seq);
    pkt_tuple->ack = __bpf_ntohl(ack);

    pkt_tuple->tran_flag = 1; // tcp包
}
/* help functions end */

/**
    accecpt an TCP connection
*/
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_exit, // 接受tcp连接
                  struct sock *sk) {    // this func return a newsk
    // bpf_printk("inet_accept_ret\n");
    if (sk == NULL) { // newsk is null
        // bpf_printk("inet_accept_ret err: newsk is null\n");
        return 0;
    }
    u64 ptid = bpf_get_current_pid_tgid(); // 获取当前进程pid

    CONN_INIT // 初始化conn_t结构中基本信息
        conn.is_server = 1;

    FILTER_DPORT     // 过滤目标端口

    FILTER_SPORT // 过滤源端口
    
    CONN_ADD_ADDRESS // conn_t结构中增加地址信息

        // 更新/插入conns_info中的键值对
        int err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    if (err) { // 更新错误
        // bpf_printk("inet_accept update err.\n");
        return 0;
    }

    return 0;
}
/**
    accecpt an TCP connection end
*/

/**
    connect an TCP connection
*/
SEC("kprobe/tcp_v4_connect") // 进入tcp_v4_connect
int BPF_KPROBE(tcp_v4_connect, const struct sock *sk) {
    // bpf_printk("tcp_v4_connect\n");
    u64 ptid = bpf_get_current_pid_tgid(); // 获取当前pid
    int err = bpf_map_update_elem(&sock_stores, &ptid, &sk, BPF_ANY);
    // 更新/插入sock_stores中的键值对
    if (err) {
        // bpf_printk("tcp_v4_connect update sock_stores err.\n");
        return 0;
    }
    return 0;
}

SEC("kretprobe/tcp_v4_connect") // 退出tcp_v4_connect
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret) {
    u64 ptid = bpf_get_current_pid_tgid(); // 获取当前pid
    struct sock **skp = bpf_map_lookup_elem(&sock_stores, &ptid);
    // 获得sock_stores中ptid对应的*sk 用skp指向
    if (skp == NULL) {
        return 0;
    }
    // bpf_printk("tcp_v4_connect_exit\n");
    if (ret != 0) { // 连接失败
        // bpf_printk("tcp_v4_connect_exit but ret %d\n", ret);
        bpf_map_delete_elem(&sock_stores, &ptid); // 删除对应键值对
        return 0;
    }
    struct sock *sk = *skp;
    CONN_INIT               // 初始化conn_t结构中基本信息
        conn.is_server = 0; // 主动连接

    FILTER_DPORT     // 过滤目标端口

    FILTER_SPORT // 过滤源端口

    CONN_ADD_ADDRESS // conn_t结构中增加地址信息

        long err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    // 更新conns_info中sk对应的conn
    if (err) {
        return 0;
    }
    return 0;
}

SEC("kprobe/tcp_v6_connect") // 进入tcp_v6_connect函数
int BPF_KPROBE(tcp_v6_connect, const struct sock *sk) {
    u64 pid = bpf_get_current_pid_tgid(); // 获取pid
    int err = bpf_map_update_elem(&sock_stores, &pid, &sk, BPF_ANY);
    // 更新sock_stores中对应pid对应的sk
    if (err) {
        return 0;
    }
    return 0;
}

SEC("kretprobe/tcp_v6_connect") // 退出tcp_v6_connect函数
int BPF_KRETPROBE(tcp_v6_connect_exit, int ret) {
    u64 ptid = bpf_get_current_pid_tgid(); // 获取pid
    struct sock **skp = bpf_map_lookup_elem(&sock_stores, &ptid);
    // 获得sock_stores中ptid对应的*sk 用skp指向
    if (skp == NULL) {
        return 0;
    }
    if (ret != 0) {                               // 错误
        bpf_map_delete_elem(&sock_stores, &ptid); // 删除对应键值对
        return 0;
    }
    struct sock *sk = *skp;

    CONN_INIT               // 初始化conn_t结构中基本信息
        conn.is_server = 0; // 主动连接

    FILTER_DPORT     // 过滤目标端口

    FILTER_SPORT // 过滤源端口

    CONN_ADD_ADDRESS // conn_t结构中增加地址信息

        long err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    // 更新conns_info中sk对应的conn
    if (err) {
        return 0;
    }
    // bpf_printk("tcp_v4_connect_exit update sk: %p.\n", sk);
    return 0;
}

/**
    connect an TCP connection end
*/

/* erase CLOSED TCP connection */
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state, struct sock *sk, int state) {
    if (all_conn) {
        return 0;
    }
    struct conn_t *value = bpf_map_lookup_elem(&conns_info, &sk);
    // 查找sk对应的conn_t
    if (state == TCP_CLOSE && value != NULL) { // TCP_CLOSE置1 说明关闭连接
        // delete
        bpf_map_delete_elem(&sock_stores, &value->ptid); // 删除sock_stores
        bpf_map_delete_elem(&conns_info, &sk);           // 删除conns_info
    }
    return 0;
}
/* erase CLOSED TCP connection end*/

/*!
in_ipv4:
    kprobe/eth_type_trans
    kprobe/ip_rcv_core.isra.0
    kprobe/tcp_v4_rcv
    kprobe/tcp_v4_do_rcv
    kprobe/skb_copy_datagram_iter

in_ipv6:
    kprobe/eth_type_trans
    kprobe/ip6_rcv_core.isra.0
    kprobe/tcp_v6_rcv
    kprobe/tcp_v6_do_rcv
    kprobe/skb_copy_datagram_iter

out_ipv4:
    kprobe/tcp_sendmsg
    kprobe/ip_queue_xmit
    kprobe/dev_queue_xmit
    kprobe/dev_hard_start_xmit

out_ipv6:
    kprobe/tcp_sendmsg
    kprobe/inet6_csk_xmit
    kprobe/dev_queue_xmit
    kprobe/dev_hard_start_xmit

*/
/************************************************ receive path
 * ****************************************/
/** in ipv4 && ipv6 */
SEC("kprobe/eth_type_trans") // 进入eth_type_trans
int BPF_KPROBE(eth_type_trans, struct sk_buff *skb) {
    const struct ethhdr *eth =
        (struct ethhdr *)BPF_CORE_READ(skb, data); // 读取里面的报文数据
    u16 protocol = BPF_CORE_READ(eth, h_proto);    // 读取包ID
    // bpf_printk("protocol: %d\n", __bpf_ntohs(protocol));
    if (protocol == __bpf_htons(ETH_P_IP)) { // Protocol is IP  0x0800
        // 14 --> sizeof(struct ethhdr)   / define
        struct iphdr *ip =
            (struct iphdr *)(BPF_CORE_READ(skb, data) +
                             14); // 链路层头部长度为14 源端口6字节
                                  // 目的端口6字节 类型2字节
        struct tcphdr *tcp = (struct tcphdr *)(BPF_CORE_READ(skb, data) +
                                               sizeof(struct iphdr) + 14);
        struct packet_tuple pkt_tuple = {0}; // 声明packet_tuple结构pkt_tuple
        get_pkt_tuple(&pkt_tuple, ip, tcp);  // 初始化pkt_tuple

        struct ktime_info *tinfo, zero = {0}; // 定义ktime_info结构zero以及tinfo

        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple, &zero);
        if (tinfo == NULL) { // 初始化失败
            // bpf_printk("v4 rx tinfo init fail.\n");
            return 0;
        }
        // 成功则获取当前内核时间并转换成毫秒
        tinfo->mac_time = bpf_ktime_get_ns() / 1000;
        // bpf_printk("v4 rx init.\n");
    } else if (protocol == __bpf_htons(ETH_P_IPV6)) { // Protocol is IPV6
        struct ipv6hdr *ip6h =
            (struct ipv6hdr *)(BPF_CORE_READ(skb, data) + 14);
        struct tcphdr *tcp = (struct tcphdr *)(BPF_CORE_READ(skb, data) +
                                               sizeof(struct ipv6hdr) + 14);
        struct packet_tuple pkt_tuple = {0};
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

        struct ktime_info *tinfo, zero = {0};

        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple, &zero);
        if (tinfo == NULL) {
            // bpf_printk("v6 rx tinfo init fail.\n");
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns() / 1000;
        // bpf_printk("v6 rx init.\n");
    }
    return 0;
}

/** in only ipv4 */
SEC("kprobe/ip_rcv_core") // 跟踪记录ipv4数据包在内核中的处理时间
int BPF_KPROBE(ip_rcv_core, struct sk_buff *skb) {
    if (!layer_time) {
        return 0;
    }
    if (skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);    // 通过skb获取ipv4包头信息
    struct tcphdr *tcp = skb_to_tcphdr(skb); // 获取tcp包头信息
    struct packet_tuple pkt_tuple = {
        0}; // 定义一个packet_tuple结构体变量pkt_tuple并初始化
    get_pkt_tuple(&pkt_tuple, ip, tcp);
    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(
        &timestamps, &pkt_tuple); // 在timestamps映射中查找元素pkt_tuple
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->ip_time = bpf_ktime_get_ns() / 1000;
    // bpf_printk("rx enter ipv4 layer.\n");
    return 0;
}
/** in only ipv6 */
SEC("kprobe/ip6_rcv_core")
int BPF_KPROBE(ip6_rcv_core, struct sk_buff *skb) {
    if (!layer_time) {
        return 0;
    }
    if (skb == NULL)
        return 0;
    struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }

    tinfo->ip_time = bpf_ktime_get_ns() / 1000;
    // bpf_printk("rx enter ipv6 layer.\n");
    return 0;
}

/**in only ipv4 */       // 接收数据包
SEC("kprobe/tcp_v4_rcv") // 记录数据包在tcpv4层时间戳
int BPF_KPROBE(tcp_v4_rcv, struct sk_buff *skb) {
    if (!layer_time) {
        return 0;
    }
    if (skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_pkt_tuple(&pkt_tuple, ip, tcp);
    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->tran_time = bpf_ktime_get_ns() / 1000;
    // bpf_printk("rx enter tcp4 layer.\n");
    return 0;
}

/** in only ipv6 */
SEC("kprobe/tcp_v6_rcv") // 接收tcpv6数据包
int BPF_KPROBE(tcp_v6_rcv, struct sk_buff *skb) {
    if (!layer_time) {
        return 0;
    }
    if (skb == NULL)
        return 0;
    struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->tran_time = bpf_ktime_get_ns() / 1000;
    // bpf_printk("rx enter tcp6 layer.\n");
    return 0;
}

// v4 & v6 do_rcv to get sk and other info
SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb) {

    if (sk == NULL || skb == NULL)
        return 0;
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        // bpf_printk("get a v4 rx pack but conn not record, its sock is:
        // %p",sk);
        return 0;
    }
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }

    CONN_INFO_TRANSFER

    // bpf_printk("rx enter tcp4_do_rcv, sk: %p \n", sk);

    CONN_ADD_EXTRA_INFO

    return 0;
}
SEC("kprobe/tcp_v6_do_rcv") // tcp层包时间
int BPF_KPROBE(tcp_v6_do_rcv, struct sock *sk, struct sk_buff *skb) {
    if (sk == NULL || skb == NULL)
        return 0;
    // bpf_printk("rx enter tcp6_do_rcv. \n");
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        // bpf_printk("get a v6 rx pack but conn not record, its sock is: %p",
        // sk);
        return 0;
    }

    struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp); // 使用ip和tcp信息填充pkt_tuple

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }

    CONN_INFO_TRANSFER

    // bpf_printk("rx enter tcp6_do_rcv, sk: %p \n", sk);

    CONN_ADD_EXTRA_INFO

    return 0;
}

/** in ipv4 && ipv6 */
SEC("kprobe/skb_copy_datagram_iter") // 处理网络数据包，记录分析包在不同网络层之间的时间差，分ipv4以及ipv6
int BPF_KPROBE(skb_copy_datagram_iter, struct sk_buff *skb) {
    if (skb == NULL)
        return 0;
    __be16 protocol = BPF_CORE_READ(skb, protocol); // 读取skb协议字段
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    struct ktime_info *tinfo;
    if (protocol == __bpf_htons(ETH_P_IP)) { /** ipv4 */

        struct iphdr *ip = skb_to_iphdr(skb);
        get_pkt_tuple(&pkt_tuple, ip, tcp);
        tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
        if (tinfo == NULL) {
            return 0;
        }

        tinfo->app_time = bpf_ktime_get_ns() / 1000;
    } else if (protocol == __bpf_ntohs(ETH_P_IPV6)) {
        /** ipv6 */
        struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        tinfo->app_time = bpf_ktime_get_ns() / 1000;
    } else {
        return 0;
    }
    /*----- record packet time info ------*/

    if (tinfo == NULL) {
        return 0;
    }
    struct sock *sk = tinfo->sk;
    if (sk == NULL) {
        return 0;
    }
    // bpf_printk("rx enter app layer.\n");

    PACKET_INIT_WITH_COMMON_INFO

    if (layer_time) {
        packet->mac_time = tinfo->ip_time - tinfo->mac_time;
        // 计算MAC层和ip层之间的时间差
        packet->ip_time = tinfo->tran_time - tinfo->ip_time;
        // 计算ip层和tcp层之间的时间差
        packet->tran_time = tinfo->app_time - tinfo->tran_time;
        // 计算tcp层和应用层之间的时间差
    }
    packet->rx = 1; // 数据包已经被接收

    // RX HTTP INFO
    if (http_info) {
        int doff =
            BPF_CORE_READ_BITFIELD_PROBED(tcp, doff); // 得用bitfield_probed
        // 读取tcp头部中的数据偏移字段
        unsigned char *user_data =
            (unsigned char *)((unsigned char *)tcp + (doff * 4));
        // 计算tcp的负载开始位置就是tcp头部之后的数据，将tcp指针指向tcp头部位置将其转换成unsigned
        // char类型
        // doff *
        // 4数据偏移值(tcp的头部长度20个字节)乘以4计算tcp头部实际字节长度，32位为单位就是4字节
        bpf_probe_read_str(packet->data, sizeof(packet->data),
                           user_data); // 将tcp负载数据读取到packet->data
    }
    bpf_ringbuf_submit(packet, 0); // 将packet提交到缓冲区
    return 0;
}

/**** end of receive path ****/

/**** receive error packet ****/
/* TCP invalid seq error */
// 根据传入的数据包提取关键信息（如IP和TCP头部信息），并将这些信息与其他元数据（如套接字信息和错误标识）一同存储到BPF
// ring buffer中
SEC("kprobe/tcp_validate_incoming") // 验证传入数据包的序列号
int BPF_KPROBE(tcp_validate_incoming, struct sock *sk, struct sk_buff *skb) {
    if (!err_packet) {
        return 0;
    }
    if (sk == NULL || skb == NULL)
        return 0;
    struct conn_t *conn =
        bpf_map_lookup_elem(&conns_info, &sk); // BPFmap查找与套接字sk关联的信息
    if (conn == NULL) {
        return 0;
    }
    struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);  // 数据包信息
    u32 start_seq = BPF_CORE_READ(tcb, seq);   // 开始序列号
    u32 end_seq = BPF_CORE_READ(tcb, end_seq); // 结束序列号
    struct tcp_sock *tp = tcp_sk(sk);          // 套接字信息
    u32 rcv_wup = BPF_CORE_READ(
        tp, rcv_wup); // 接收方已经确认并准备接收的数据最后一个字节的序列号
    u32 rcv_nxt =
        BPF_CORE_READ(tp, rcv_nxt); // 期望发送发下次发送的数据字节序列号
    u32 rcv_wnd = BPF_CORE_READ(tp, rcv_wnd);         // tcp接收窗口大小
    u32 receive_window = rcv_wup + rcv_nxt - rcv_wnd; // 当前可用的接收窗口
    receive_window = 0;

    if (end_seq >= rcv_wup && rcv_nxt + receive_window >= start_seq) {
        // bpf_printk("error_identify: tcp seq validated. \n");
        return 0;
        // 检查数据包序列号是否在接收窗口内
    }
    // bpf_printk("error_identify: tcp seq err. \n");
    //  invalid seq
    u16 family = BPF_CORE_READ(
        sk, __sk_common.skc_family); // 获取套接字的地址族就是获得当前ip协议
    struct packet_tuple pkt_tuple = {0};
    if (family == AF_INET) {
        struct iphdr *ip = skb_to_iphdr(skb);
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        get_pkt_tuple(&pkt_tuple, ip, tcp);
    } else if (family == AF_INET6) {
        struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);
    } else {
        return 0;
    }
    struct pack_t *packet;
    packet = bpf_ringbuf_reserve(&rb, sizeof(*packet), 0);
    if (!packet) {
        return 0;
    }
    packet->err = 1; // 错误标记此数据包有问题
    packet->sock = sk;
    packet->ack = pkt_tuple.ack;
    packet->seq = pkt_tuple.seq;
    bpf_ringbuf_submit(packet, 0);
    return 0;
}
// 跟踪网络数据包检测tcp检验和错误
/* TCP invalid checksum error*/
SEC("kretprobe/__skb_checksum_complete")
int BPF_KRETPROBE(__skb_checksum_complete_exit, int ret) {
    if (!err_packet) {
        return 0;
    }
    u64 pid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&sock_stores, &pid);
    if (skp == NULL) {
        return 0;
    }
    if (ret == 0) {
        // bpf_printk("error_identify: tcp checksum validated. \n");
        return 0;
    }
    // bpf_printk("error_identify: tcp checksum error. \n");
    struct sock *sk = *skp;
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        return 0;
    }
    struct pack_t *packet;
    packet = bpf_ringbuf_reserve(&rb, sizeof(*packet), 0);
    if (!packet) {
        return 0;
    }
    packet->err = 2;   // 校验和错误
    packet->sock = sk; // 存储socket信息到sock字段中
    bpf_ringbuf_submit(packet, 0);

    return 0;
}

/**** receive error packet end ****/

/**** send path ****/
/*!
 * \brief: 获取数据包进入TCP层时刻的时间戳, 发送tcp层起始点
 *         out ipv4 && ipv6
 */
SEC("kprobe/tcp_sendmsg") // 跟踪tcp发送包信息
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {

    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        return 0;
    }

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    struct ktime_info *tinfo, zero = {0}; // 存储时间
    struct packet_tuple pkt_tuple = {0};  // 存储数据包信息
    /** ipv4 */
    if (family == AF_INET) {
        u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        pkt_tuple.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr); // 源ip
        pkt_tuple.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr); // 目的ip
        pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);   // 源端口
        pkt_tuple.dport = __bpf_ntohs(dport); // 目的端口并进行字节序转换

        u32 snd_nxt =
            BPF_CORE_READ(tcp_sk(sk), snd_nxt); // tcp要发送的下一个字节序列号
        u32 rcv_nxt = BPF_CORE_READ(tcp_sk(sk),
                                    rcv_nxt); // tcp接收的下一个字节的期望序列号
        pkt_tuple.seq = snd_nxt;
        pkt_tuple.ack = rcv_nxt;
        pkt_tuple.tran_flag = TCP;
        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple,
            &zero); // timestamps的BPF map保存数据包与时间戳的映射
        if (tinfo == NULL) {
            return 0;
        }
        tinfo->tran_time = bpf_ktime_get_ns() / 1000;
    } else if (family == AF_INET6) {
        // 读取ipv6源地址
        bpf_probe_read_kernel(
            &pkt_tuple.saddr_v6,
            sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        // 获取ipv6目的地址
        bpf_probe_read_kernel(
            &pkt_tuple.daddr_v6,
            sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        // sk套接字中获取源端口号
        pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        // 获取目的端口
        u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        pkt_tuple.dport = __bpf_ntohs(dport);

        u32 snd_nxt =
            BPF_CORE_READ(tcp_sk(sk), snd_nxt); // 发送的下一个字节序列号
        u32 rcv_nxt =
            BPF_CORE_READ(tcp_sk(sk), rcv_nxt); // 期望接收的下一个字节序列号
        pkt_tuple.seq = snd_nxt;
        pkt_tuple.ack = rcv_nxt;
        pkt_tuple.tran_flag = TCP;

        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple, &zero);
        if (tinfo == NULL) {
            return 0;
        }
        tinfo->tran_time = bpf_ktime_get_ns() / 1000;
    }

    CONN_INFO_TRANSFER

    CONN_ADD_EXTRA_INFO

    // TX HTTP info
    if (http_info) {
        unsigned char *user_data = BPF_CORE_READ(msg, msg_iter.iov, iov_base);
        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple, &zero);
        if (tinfo == NULL) {
            return 0;
        }
        bpf_probe_read_str(tinfo->data, sizeof(tinfo->data), user_data);
    }
    return 0;
}

/*!
* \brief: 获取数据包进入IP层时刻的时间戳
* tips:   此时ip数据段还没有数据，不能用 get_pkt_tuple(&pkt_tuple, ip,
tcp)获取ip段的数据 out only ipv4
*/
SEC("kprobe/ip_queue_xmit")
int BPF_KPROBE(ip_queue_xmit, struct sock *sk, struct sk_buff *skb) {
    if (!layer_time) {
        return 0;
    }
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    struct packet_tuple pkt_tuple = {0};
    struct ktime_info *tinfo;
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    if (family == AF_INET) {
        u16 dport;
        u32 seq, ack;
        pkt_tuple.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        pkt_tuple.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        pkt_tuple.dport = __bpf_ntohs(dport);
        seq = BPF_CORE_READ(tcp, seq);
        ack = BPF_CORE_READ(tcp, ack_seq);
        pkt_tuple.seq = __bpf_ntohl(seq);
        pkt_tuple.ack = __bpf_ntohl(ack);
        pkt_tuple.tran_flag = TCP;
        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        tinfo->ip_time = bpf_ktime_get_ns() / 1000;
    }
    return 0;
};

/*!
* \brief: 获取数据包进入IP层时刻的时间戳
* tips:   此时ip数据段还没有数据，不能用 get_pkt_tuple(&pkt_tuple, ip,
tcp)获取ip段的数据 out only ipv6
*/
SEC("kprobe/inet6_csk_xmit")
int BPF_KPROBE(inet6_csk_xmit, struct sock *sk, struct sk_buff *skb) {
    if (!layer_time) {
        return 0;
    }
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    struct ktime_info *tinfo;
    if (family == AF_INET6) {
        u16 dport;
        u32 seq, ack;

        bpf_probe_read_kernel(
            &pkt_tuple.saddr_v6,
            sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

        bpf_probe_read_kernel(
            &pkt_tuple.daddr_v6,
            sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        pkt_tuple.dport = __bpf_ntohs(dport);
        seq = BPF_CORE_READ(tcp, seq);
        ack = BPF_CORE_READ(tcp, ack_seq);
        pkt_tuple.seq = __bpf_ntohl(seq);
        pkt_tuple.ack = __bpf_ntohl(ack);
        pkt_tuple.tran_flag = TCP;
        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        tinfo->ip_time = bpf_ktime_get_ns() / 1000;
    }
    return 0;
};

/*!
* \brief: 获取数据包进入数据链路层时刻的时间戳
    out ipv4 && ipv6
*/
SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(__dev_queue_xmit, struct sk_buff *skb) {
    if (!layer_time) {
        return 0;
    }
    // 从skb中读取以太网头部
    const struct ethhdr *eth = (struct ethhdr *)BPF_CORE_READ(skb, data);
    u16 protocol = BPF_CORE_READ(
        eth,
        h_proto); // 以太网头部协议字段该字段存储的是以太网帧所封装的上层协议类型
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    struct ktime_info *tinfo;
    if (protocol == __bpf_ntohs(ETH_P_IP)) {
        /** ipv4 */
        struct iphdr *ip = skb_to_iphdr(skb);
        get_pkt_tuple(&pkt_tuple, ip, tcp);

        // FILTER_DPORT
        // FILTER_SPORT

        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns() / 1000;
    } else if (protocol == __bpf_ntohs(ETH_P_IPV6)) {
        /** ipv6 */
        struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns() / 1000;
    }
    return 0;
};

/*!
* \brief: 获取数据包发送时刻的时间戳
    out ipv4 && ipv6
*/
SEC("kprobe/dev_hard_start_xmit")
int BPF_KPROBE(dev_hard_start_xmit, struct sk_buff *skb) {
    const struct ethhdr *eth = (struct ethhdr *)BPF_CORE_READ(skb, data);
    u16 protocol = BPF_CORE_READ(eth, h_proto);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    struct ktime_info *tinfo;
    if (protocol == __bpf_ntohs(ETH_P_IP)) {
        /** ipv4 */
        struct iphdr *ip = skb_to_iphdr(skb);
        get_pkt_tuple(&pkt_tuple, ip, tcp);

        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        // 数据包在队列中等待的时间
        tinfo->qdisc_time = bpf_ktime_get_ns() / 1000;
    } else if (protocol == __bpf_ntohs(ETH_P_IPV6)) {
        /** ipv6 */
        struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        tinfo->qdisc_time = bpf_ktime_get_ns() / 1000;
    } else {
        return 0;
    }

    /*----- record packet time info ------*/
    if (tinfo == NULL) {
        return 0;
    }
    struct sock *sk = tinfo->sk;
    if (!sk) {
        return 0;
    }
    PACKET_INIT_WITH_COMMON_INFO
    // 记录各层的时间差值
    if (layer_time) {
        packet->tran_time = tinfo->ip_time - tinfo->tran_time;
        packet->ip_time = tinfo->mac_time - tinfo->ip_time;
        packet->mac_time =
            tinfo->qdisc_time -
            tinfo
                ->mac_time; // 队列纪律层，处于网络协议栈最底层，负责实际数据传输与接收
    }

    packet->rx = 0; // 发送一个数据包

    // TX HTTP Info
    if (http_info) {
        bpf_probe_read_str(packet->data, sizeof(packet->data), tinfo->data);
        bpf_printk("%s", packet->data);
    }
    bpf_ringbuf_submit(packet, 0);

    return 0;
};
/**** send path end ****/

/**** retrans ****/

/* 在进入快速恢复阶段时，不管是基于Reno或者SACK的快速恢复，
 * 还是RACK触发的快速恢复，都将使用函数tcp_enter_recovery进入
 * TCP_CA_Recovery拥塞阶段。
 */
SEC("kprobe/tcp_enter_recovery") // tcp连接进入恢复状态调用
int BPF_KPROBE(tcp_enter_recovery, struct sock *sk) {
    if (!retrans_info) {
        return 0;
    }
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        // bpf_printk("get a v4 rx pack but conn not record, its sock is: %p",
        // sk);
        return 0;
    }
    conn->fastRe += 1; // 统计进入tcp恢复状态的次数

    return 0;
}

/* Enter Loss state. If we detect SACK reneging, forget all SACK information
 * and reset tags completely, otherwise preserve SACKs. If receiver
 * dropped its ofo queue, we will know this due to reneging detection.
 * 在报文的重传定时器到期时，在tcp_retransmit_timer函数中，进入TCP_CA_Loss拥塞状态。
 */
SEC("kprobe/tcp_enter_loss")
int BPF_KPROBE(tcp_enter_loss, struct sock *sk) {
    if (!retrans_info) {
        return 0;
    }
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        return 0;
    }
    conn->timeout += 1;
    return 0;
}

/**** retrans end ****/

/* new */

SEC("kprobe/udp_rcv")
int BPF_KPROBE(udp_rcv, struct sk_buff *skb) {
    if (!udp_info)
        return 0;
    if (skb == NULL) // 判断是否为空
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct udphdr *udp = skb_to_udphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_udp_pkt_tuple(&pkt_tuple, ip, udp);
    struct ktime_info *tinfo, zero = {0};
    tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&timestamps,
                                                            &pkt_tuple, &zero);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->tran_time = bpf_ktime_get_ns() / 1000;
    return 0;
}

SEC("kprobe/__udp_enqueue_schedule_skb")
int BPF_KPROBE(__udp_enqueue_schedule_skb, struct sock *sk,
               struct sk_buff *skb) {
    if (!udp_info)
        return 0;
    if (skb == NULL) // 判断是否为空
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct udphdr *udp = skb_to_udphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    pkt_tuple.daddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    pkt_tuple.saddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    pkt_tuple.dport = BPF_CORE_READ(sk, __sk_common.skc_num);
    pkt_tuple.sport = __bpf_ntohs(dport);
    pkt_tuple.tran_flag = 2;
    struct ktime_info *tinfo, zero = {0};
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    struct udp_message *message;
    struct udp_message *udp_message =
        bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    ;
    message = bpf_ringbuf_reserve(&udp_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }
    message->tran_time = bpf_ktime_get_ns() / 1000 - tinfo->tran_time;
    message->saddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    message->daddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    message->sport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    message->dport = BPF_CORE_READ(sk, __sk_common.skc_num);
    message->rx=0;//收包
    message->len=__bpf_ntohs(BPF_CORE_READ(udp,len));
    bpf_ringbuf_submit(message, 0);
    return 0;
}
SEC("kprobe/udp_send_skb")
int BPF_KPROBE(udp_send_skb, struct sk_buff *skb,struct flowi4 *fl4) {
     if (!udp_info)
        return 0;
    if (skb == NULL) // 判断是否为空
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    
    struct udphdr *udp = skb_to_udphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_udp_pkt_tuple(&pkt_tuple, ip, udp);

    struct sock *sk = BPF_CORE_READ(skb, sk);

    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    pkt_tuple.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    pkt_tuple.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    pkt_tuple.dport = __bpf_ntohs(dport);
    pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    pkt_tuple.tran_flag = UDP;
    struct ktime_info *tinfo, zero = {0};
    tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&timestamps,
                                                            &pkt_tuple, &zero);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->tran_time = bpf_ktime_get_ns() / 1000;

    unsigned int pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pid_UDP, &pid, &pkt_tuple, BPF_ANY);

    return 0;
}
SEC("kprobe/ip_send_skb")
int BPF_KPROBE(ip_send_skb, struct net *net,struct sk_buff *skb) {
     if (!udp_info)
        return 0;
    if (skb == NULL) // 判断是否为空
        return 0;
    unsigned int pid = bpf_get_current_pid_tgid();
    struct packet_tuple *pt = bpf_map_lookup_elem(&pid_UDP, &pid);
    if (!pt) {
        return 0;
    }

    struct ktime_info *tinfo, zero = {0};
    struct udphdr *udp = skb_to_udphdr(skb);
    tinfo = bpf_map_lookup_elem(&timestamps, pt);
    if (tinfo == NULL) {
        return 0;
    }
    struct udp_message *message;
    struct udp_message *udp_message =
        bpf_map_lookup_elem(&timestamps, pt);
    message = bpf_ringbuf_reserve(&udp_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }
    message->tran_time = bpf_ktime_get_ns() / 1000 - tinfo->tran_time;
    message->saddr = pt->saddr;
    message->daddr = pt->daddr;
    message->sport = pt->sport;
    message->dport = pt->dport;
    message->rx=1;
    message->len=__bpf_ntohs(BPF_CORE_READ(udp,len));
    bpf_ringbuf_submit(message, 0);
    return 0;
}