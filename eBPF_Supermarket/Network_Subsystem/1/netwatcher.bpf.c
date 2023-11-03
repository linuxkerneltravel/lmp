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

struct ktime_info {                      // us time stamp info
    unsigned long long qdisc_time;       // tx包离开mac层时间戳
    unsigned long long mac_time;         // tx、rx包到达mac层时间戳
    unsigned long long ip_time;          // tx、rx包到达ip层时间戳
    unsigned long long tcp_time;         // tx、rx包到达tcp层时间戳
    unsigned long long app_time;         // rx包离开tcp层时间戳
    void *sk;                            // 此包所属 socket
    unsigned char data[MAX_HTTP_HEADER]; // 用户层数据
};

struct packet_tuple {
    unsigned __int128 saddr_v6;
    unsigned __int128 daddr_v6;
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned int seq;
    unsigned int ack;
};

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
    void *val;
    long err;

    val = bpf_map_lookup_elem(map, key);
    if (val)
        return val;

    err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
    if (err && err != -EEXIST)
        return 0;

    return bpf_map_lookup_elem(map, key);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_CONN 1000

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN *MAX_PACKET);
    __type(key, struct packet_tuple);
    __type(value, struct ktime_info);
} timestamps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN);
    __type(key, struct sock *);
    __type(value, struct conn_t);
} conns_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN);
    __type(key, u64);
    __type(value, struct sock *);
} sock_stores SEC(".maps");

const volatile int filter_dport = 0;
const volatile int filter_sport = 0;
const volatile int all_conn = 0, err_packet = 0, extra_conn_info = 0,
                   layer_time = 0, http_info = 0, retrans_info = 0;

/* help macro */
#define FILTER_DPORT                                                           \
    if (filter_dport) {                                                        \
        if (conn.dport != filter_dport) {                                      \
            return 0;                                                          \
        }                                                                      \
    }
#define FILTER_SPORT                                                           \
    if (filter_sport) {                                                        \
        if (conn.sport != filter_sport) {                                      \
            return 0;                                                          \
        }                                                                      \
    }

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

#define CONN_INFO_TRANSFER tinfo->sk = conn->sock;

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
static struct tcp_sock *tcp_sk(const struct sock *sk) {
    return (struct tcp_sock *)sk;
}

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb) {
    return (struct tcphdr *)((BPF_CORE_READ(skb, head) +
                              BPF_CORE_READ(skb, transport_header)));
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb) {
    return (struct iphdr *)(BPF_CORE_READ(skb, head) +
                            BPF_CORE_READ(skb, network_header));
}

static inline struct ipv6hdr *skb_to_ipv6hdr(const struct sk_buff *skb) {
    return (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                              BPF_CORE_READ(skb, network_header));
}

static void get_pkt_tuple(struct packet_tuple *pkt_tuple, struct iphdr *ip,
                          struct tcphdr *tcp) {
    pkt_tuple->saddr = BPF_CORE_READ(ip, saddr);
    pkt_tuple->daddr = BPF_CORE_READ(ip, daddr);
    u16 sport = BPF_CORE_READ(tcp, source);
    u16 dport = BPF_CORE_READ(tcp, dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    pkt_tuple->dport = __bpf_ntohs(dport);
    u32 seq = BPF_CORE_READ(tcp, seq);
    u32 ack = BPF_CORE_READ(tcp, ack_seq);
    pkt_tuple->seq = __bpf_ntohl(seq);
    pkt_tuple->ack = __bpf_ntohl(ack);
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
}
/* help functions end */

/**
    accecpt an TCP connection
*/
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_exit,
                  struct sock *sk) { // this func return a newsk
    // bpf_printk("inet_accept_ret\n");
    if (sk == NULL) {
        // bpf_printk("inet_accept_ret err: newsk is null\n");
        return 0;
    }
    u64 ptid = bpf_get_current_pid_tgid();

    CONN_INIT
    conn.is_server = 1;

    FILTER_DPORT
    FILTER_SPORT

    CONN_ADD_ADDRESS

    int err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    if (err) {
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
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, const struct sock *sk) {
    // bpf_printk("tcp_v4_connect\n");
    u64 ptid = bpf_get_current_pid_tgid();
    int err = bpf_map_update_elem(&sock_stores, &ptid, &sk, BPF_ANY);
    if (err) {
        // bpf_printk("tcp_v4_connect update sock_stores err.\n");
        return 0;
    }
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret) {
    u64 ptid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&sock_stores, &ptid);
    if (skp == NULL) {
        return 0;
    }
    // bpf_printk("tcp_v4_connect_exit\n");
    if (ret != 0) {
        // bpf_printk("tcp_v4_connect_exit but ret %d\n", ret);
        bpf_map_delete_elem(&sock_stores, &ptid);
        return 0;
    }
    struct sock *sk = *skp;
    CONN_INIT
    conn.is_server = 0;

    FILTER_DPORT
    FILTER_SPORT

    CONN_ADD_ADDRESS

    long err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    if (err) {
        // bpf_printk("tcp_v4_connect_exit update err.\n");
        return 0;
    }
    // bpf_printk("tcp_v4_connect_exit update sk: %p\n", sk);
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, const struct sock *sk) {
    // bpf_printk("tcp_v6_connect\n");
    u64 pid = bpf_get_current_pid_tgid();
    int err = bpf_map_update_elem(&sock_stores, &pid, &sk, BPF_ANY);
    if (err) {
        // bpf_printk("tcp_v6_connect update sock_stores err.\n");
        return 0;
    }
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_exit, int ret) {
    u64 ptid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&sock_stores, &ptid);
    if (skp == NULL) {
        return 0;
    }
    // bpf_printk("tcp_v6_connect_exit\n");
    if (ret != 0) {
        // bpf_printk("tcp_v6_connect_exit but return %d\n", ret);
        bpf_map_delete_elem(&sock_stores, &ptid);
        return 0;
    }
    struct sock *sk = *skp;

    CONN_INIT
    conn.is_server = 0;

    FILTER_DPORT
    FILTER_SPORT

    CONN_ADD_ADDRESS

    long err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    if (err) {
        // bpf_printk("tcp_v6_connect_exit update err.\n");
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
    if (state == TCP_CLOSE && value != NULL) {
        // delete
        bpf_map_delete_elem(&sock_stores, &value->ptid);
        bpf_map_delete_elem(&conns_info, &sk);
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
SEC("kprobe/eth_type_trans")
int BPF_KPROBE(eth_type_trans, struct sk_buff *skb) {
    const struct ethhdr *eth = (struct ethhdr *)BPF_CORE_READ(skb, data);
    u16 protocol = BPF_CORE_READ(eth, h_proto);
    // bpf_printk("protocol: %d\n", __bpf_ntohs(protocol));
    if (protocol == __bpf_htons(ETH_P_IP)) { // Protocol is IP
        struct iphdr *ip = (struct iphdr *)(BPF_CORE_READ(skb, data) + 14);
        struct tcphdr *tcp = (struct tcphdr *)(BPF_CORE_READ(skb, data) +
                                               sizeof(struct iphdr) + 14);
        struct packet_tuple pkt_tuple = {0};
        get_pkt_tuple(&pkt_tuple, ip, tcp);

        struct ktime_info *tinfo, zero = {0};

        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple, &zero);
        if (tinfo == NULL) {
            // bpf_printk("v4 rx tinfo init fail.\n");
            return 0;
        }
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
SEC("kprobe/ip_rcv_core")
int BPF_KPROBE(ip_rcv_core, struct sk_buff *skb) {
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

/**in only ipv4 */
SEC("kprobe/tcp_v4_rcv")
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
    tinfo->tcp_time = bpf_ktime_get_ns() / 1000;
    // bpf_printk("rx enter tcp4 layer.\n");
    return 0;
}

/** in only ipv6 */
SEC("kprobe/tcp_v6_rcv")
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
    tinfo->tcp_time = bpf_ktime_get_ns() / 1000;
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
        // bpf_printk("get a v4 rx pack but conn not record, its sock is: %p",
        // sk);
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
SEC("kprobe/tcp_v6_do_rcv")
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
    get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

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
SEC("kprobe/skb_copy_datagram_iter")
int BPF_KPROBE(skb_copy_datagram_iter, struct sk_buff *skb) {
    if (skb == NULL)
        return 0;
    __be16 protocol = BPF_CORE_READ(skb, protocol);
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
        packet->ip_time = tinfo->tcp_time - tinfo->ip_time;
        packet->tcp_time = tinfo->app_time - tinfo->tcp_time;
    }
    packet->rx = 1;

    // RX HTTP INFO
    if (http_info) {
        int doff =
            BPF_CORE_READ_BITFIELD_PROBED(tcp, doff); // 得用bitfield_probed
        unsigned char *user_data =
            (unsigned char *)((unsigned char *)tcp + (doff * 4));
        bpf_probe_read_str(packet->data, sizeof(packet->data), user_data);
    }
    bpf_ringbuf_submit(packet, 0);
    return 0;
}

/**** end of receive path ****/

/**** receive error packet ****/
/* TCP invalid seq error */
SEC("kprobe/tcp_validate_incoming")
int BPF_KPROBE(tcp_validate_incoming, struct sock *sk, struct sk_buff *skb) {
    if (!err_packet) {
        return 0;
    }
    if (sk == NULL || skb == NULL)
        return 0;
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        return 0;
    }
    struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
    u32 start_seq = BPF_CORE_READ(tcb, seq);
    u32 end_seq = BPF_CORE_READ(tcb, end_seq);
    struct tcp_sock *tp = tcp_sk(sk);
    u32 rcv_wup = BPF_CORE_READ(tp, rcv_wup);
    u32 rcv_nxt = BPF_CORE_READ(tp, rcv_nxt);
    u32 rcv_wnd = BPF_CORE_READ(tp, rcv_wnd);
    u32 receive_window = rcv_wup + rcv_nxt - rcv_wnd;
    if (receive_window < 0)
        receive_window = 0;

    if (end_seq >= rcv_wup && rcv_nxt + receive_window >= start_seq) {
        // bpf_printk("error_identify: tcp seq validated. \n");
        return 0;
    }
    // bpf_printk("error_identify: tcp seq err. \n");
    //  invalid seq
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
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
    packet->err = 1;
    packet->sock = sk;
    packet->ack = pkt_tuple.ack;
    packet->seq = pkt_tuple.seq;
    bpf_ringbuf_submit(packet, 0);
    return 0;
}

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
    packet->err = 2;
    packet->sock = sk;
    bpf_ringbuf_submit(packet, 0);

    return 0;
}

/**** receive error packet end ****/

/**** send path ****/
/*!
 * \brief: 获取数据包进入TCP层时刻的时间戳, 发送tcp层起始点
 *         out ipv4 && ipv6
 */
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {

    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        return 0;
    }

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    struct ktime_info *tinfo, zero = {0};
    struct packet_tuple pkt_tuple = {0};
    /** ipv4 */
    if (family == AF_INET) {
        u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        pkt_tuple.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        pkt_tuple.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        pkt_tuple.dport = __bpf_ntohs(dport);

        u32 snd_nxt = BPF_CORE_READ(tcp_sk(sk), snd_nxt);
        u32 rcv_nxt = BPF_CORE_READ(tcp_sk(sk), rcv_nxt);
        pkt_tuple.seq = snd_nxt;
        pkt_tuple.ack = rcv_nxt;

        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple, &zero);
        if (tinfo == NULL) {
            return 0;
        }
        tinfo->tcp_time = bpf_ktime_get_ns() / 1000;
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(
            &pkt_tuple.saddr_v6,
            sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

        bpf_probe_read_kernel(
            &pkt_tuple.daddr_v6,
            sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

        pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
        u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
        pkt_tuple.dport = __bpf_ntohs(dport);

        u32 snd_nxt = BPF_CORE_READ(tcp_sk(sk), snd_nxt);
        u32 rcv_nxt = BPF_CORE_READ(tcp_sk(sk), rcv_nxt);
        pkt_tuple.seq = snd_nxt;
        pkt_tuple.ack = rcv_nxt;

        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple, &zero);
        if (tinfo == NULL) {
            return 0;
        }
        tinfo->tcp_time = bpf_ktime_get_ns() / 1000;
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
    const struct ethhdr *eth = (struct ethhdr *)BPF_CORE_READ(skb, data);
    u16 protocol = BPF_CORE_READ(eth, h_proto);
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
    if (sk == NULL) {
        return 0;
    }

    PACKET_INIT_WITH_COMMON_INFO

    if (layer_time) {
        packet->tcp_time = tinfo->ip_time - tinfo->tcp_time;
        packet->ip_time = tinfo->mac_time - tinfo->ip_time;
        packet->mac_time = tinfo->qdisc_time - tinfo->mac_time;
    }
    packet->rx = 0;

    // TX HTTP Info
    if (http_info) {
        bpf_probe_read_str(packet->data, sizeof(packet->data), tinfo->data);
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
SEC("kprobe/tcp_enter_recovery")
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
    conn->fastRe += 1;

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
        // bpf_printk("get a v4 rx pack but conn not record, its sock is: %p",
        // sk);
        return 0;
    }
    conn->timeout += 1;
    return 0;
}

/**** retrans end ****/
