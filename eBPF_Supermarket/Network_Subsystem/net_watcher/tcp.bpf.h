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
// netwatcher libbpf tcp

#include "common.bpf.h"

static __always_inline
int __inet_csk_accept(struct sock *sk)
{
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

static __always_inline
int __tcp_v4_connect(const struct sock *sk)
{
    u64 ptid = bpf_get_current_pid_tgid(); // 获取当前pid
    int err = bpf_map_update_elem(&sock_stores, &ptid, &sk, BPF_ANY);
    // 更新/插入sock_stores中的键值对
    if (err) {
        // bpf_printk("tcp_v4_connect update sock_stores err.\n");
        return 0;
    }
    return 0;
}

static __always_inline
int __tcp_v4_connect_exit(int ret)
{
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

static __always_inline
int __tcp_v6_connect(const struct sock *sk)
{
    u64 pid = bpf_get_current_pid_tgid(); // 获取pid
    int err = bpf_map_update_elem(&sock_stores, &pid, &sk, BPF_ANY);
    // 更新sock_stores中对应pid对应的sk
    if (err) {
        return 0;
    }
    return 0;
}

static __always_inline
int __tcp_v6_connect_exit(int ret)
{
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
static __always_inline
int __tcp_set_state( struct sock *sk, int state)
{
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

// receive error packet
static __always_inline
int __tcp_validate_incoming(struct sock *sk, struct sk_buff *skb)
{
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
static __always_inline
int skb_checksum_complete(int ret)
{
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
////retrans packet
static __always_inline
int __tcp_enter_recovery(struct sock *sk)
{
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
static __always_inline
int __tcp_enter_loss(struct sock *sk)
{
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
static __always_inline
int __handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    struct sock *sk = (struct sock *)ctx->skaddr;
    __u64 *before_time, new_time, time;

    before_time = bpf_map_lookup_elem(&tcp_state, &sk);
    new_time= bpf_ktime_get_ns();
    if (!before_time)
        time = 0;
    else
        time = (new_time - *before_time) / 1000;
    struct tcpstate tcpstate = {};
    tcpstate.oldstate = ctx->oldstate;
    tcpstate.newstate = ctx->newstate;
    tcpstate.family = ctx->family;
    tcpstate.sport = ctx->sport;
    tcpstate.dport = ctx->dport;
    bpf_probe_read_kernel(&tcpstate.saddr, sizeof(tcpstate.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&tcpstate.daddr, sizeof(tcpstate.daddr), &sk->__sk_common.skc_daddr);
    tcpstate.time = time;
    if (ctx->newstate == TCP_CLOSE)
        bpf_map_delete_elem(&tcp_state, &sk);
    else
        bpf_map_update_elem(&tcp_state, &sk, &new_time, BPF_ANY);

    struct tcp_state  *message;
    message = bpf_ringbuf_reserve(&tcp_rb, sizeof(*message), 0);
    if(!message){
        return 0;
    }
    message->saddr = tcpstate.saddr;
    message->daddr = tcpstate.daddr;
    message->sport = tcpstate.sport;
    message->dport = tcpstate.dport;
    message->oldstate = tcpstate.oldstate;
    message->newstate = tcpstate.newstate;
    message->time =  tcpstate.time;
    bpf_ringbuf_submit(message, 0);
    return 0;
}