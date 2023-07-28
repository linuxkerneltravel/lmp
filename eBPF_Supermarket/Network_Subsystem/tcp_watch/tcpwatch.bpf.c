#include "tcpwatch.h"
#include "vmlinux.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct ktime_info { // us time stamp info
    unsigned long long qdisc_time;
    unsigned long long mac_time;
    unsigned long long ip_time;
    unsigned long long tcp_time;
    unsigned long long app_time;
    void *sk;
    char comm[MAX_COMM];
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
    __type(key, u32);
    __type(value, struct sock *);
} sock_stores SEC(".maps");

const volatile int filter_dport = 0;
const volatile int filter_sport = 0;

#define FILTER_DPORT                                                           \
    if (filter_dport) {                                                        \
        if (dport != filter_dport) {                                           \
            return 0;                                                          \
        }                                                                      \
    }
#define FILTER_SPORT                                                           \
    if (filter_sport) {                                                        \
        if (sport != filter_sport) {                                           \
            return 0;                                                          \
        }                                                                      \
    }

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

/**
    accecpt an TCP connection
*/
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *newsk) {
    bpf_printk("inet_accept_ret\n");
    if (newsk == NULL) {
        bpf_printk("inet_accept_ret err: newsk is null\n");
        return 0;
    }

    u16 protocol = BPF_CORE_READ(newsk, sk_protocol);
    if (protocol != IPPROTO_TCP)
        return 0;
    struct conn_t conn = {};
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));
    conn.sock = newsk;

    u16 family = BPF_CORE_READ(newsk, __sk_common.skc_family);
    __be16 dport = BPF_CORE_READ(newsk, __sk_common.skc_dport);
    u16 sport = BPF_CORE_READ(newsk, __sk_common.skc_num);

    conn.family = family;
    conn.sport = sport;
    conn.dport = __bpf_ntohs(dport);

    // ##FILTER_PORT##

    if (family == AF_INET) {
        conn.saddr = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
        conn.daddr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(
            &conn.saddr_v6,
            sizeof(newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
            &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(
            &conn.daddr_v6,
            sizeof(newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
            &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    conn.init_timestamp = bpf_ktime_get_ns() / 1000;
    conn.ptid = bpf_get_current_pid_tgid();

    int err = bpf_map_update_elem(&conns_info, &newsk, &conn, BPF_ANY);
    if (err) {
        bpf_printk("inet_accept update err.\n");
        return 0;
    }

    return 0;
}

/**
    connect an TCP connection
*/
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, const struct sock *sk) {
    bpf_printk("tcp_v4_connect\n");
    u32 pid = bpf_get_current_pid_tgid();
    int err = bpf_map_update_elem(&sock_stores, &pid, &sk, BPF_ANY);
    if (err) {
        bpf_printk("tcp_v4_connect update sock_stores err.\n");
        return 0;
    }
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret) {
    u32 pid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&sock_stores, &pid);
    if (skp == NULL) {
        return 0;
    }
    bpf_printk("tcp_v4_connect_exit\n");
    if (ret != 0) {
        bpf_printk("tcp_v4_connect_exit but ret %d\n", ret);
        bpf_map_delete_elem(&sock_stores, &pid);
        return 0;
    }
    struct sock *sk = *skp;
    struct conn_t conn = {};
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));
    conn.sock = sk;
    conn.ptid = pid;
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    conn.family = family;
    conn.sport = sport;
    conn.dport = __bpf_ntohs(dport);

    // ##FILTER_PORT##

    conn.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    conn.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    conn.init_timestamp = bpf_ktime_get_ns() / 1000;

    long err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    if (err) {
        bpf_printk("tcp_v4_connect_exit update err.\n");
        return 0;
    }
    bpf_printk("tcp_v4_connect_exit update sk: %p\n", sk);
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, const struct sock *sk) {
    bpf_printk("tcp_v6_connect\n");
    u32 pid = bpf_get_current_pid_tgid();
    int err = bpf_map_update_elem(&sock_stores, &pid, &sk, BPF_ANY);
    if (err) {
        bpf_printk("tcp_v6_connect update sock_stores err.\n");
        return 0;
    }
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_exit, int ret) {
    u32 pid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&sock_stores, &pid);
    if (skp == NULL) {
        return 0;
    }
    bpf_printk("tcp_v6_connect_exit\n");
    if (ret != 0) {
        bpf_printk("tcp_v6_connect_exit but return %d\n", ret);
        bpf_map_delete_elem(&sock_stores, &pid);
        return 0;
    }
    struct sock *sk = *skp;
    struct conn_t conn = {};
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));
    conn.sock = sk;
    conn.ptid = pid;
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    __be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);

    conn.family = family;
    conn.sport = sport;
    conn.dport = __bpf_ntohs(dport);

    // ##FILTER_PORT##

    bpf_probe_read_kernel(
        &conn.saddr_v6,
        sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
        &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&conn.daddr_v6,
                          sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
                          &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    conn.init_timestamp = bpf_ktime_get_ns() / 1000;

    long err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    if (err) {
        bpf_printk("tcp_v6_connect_exit update err.\n");
        return 0;
    }
    bpf_printk("tcp_v4_connect_exit update sk: %p.\n", sk);
    return 0;
}

/* TCP State */
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state, struct sock *sk, int state) {
    struct conn_t *value = bpf_map_lookup_elem(&conns_info, &sk);
    if (state == TCP_CLOSE && value != NULL) {
        // delete
        // bpf_map_delete_elem(&sock_stores, &value->ptid);
        // bpf_map_delete_elem(&conns_info, &sk);
    }
    return 0;
}

/*!
in_ipv4:
    kprobe/eth_type_trans
    kprobe/ip_rcv_core.isra.0
    kprobe/tcp_v4_rcv
    kprobe/skb_copy_datagram_iter

in_ipv6:
    kprobe/eth_type_trans
    kprobe/ip6_rcv_core.isra.0
    kprobe/tcp_v6_rcv
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
    bpf_printk("protocol: %d\n", __bpf_ntohs(protocol));
    if (protocol == __bpf_htons(ETH_P_IP)) { // Protocol is IP
        struct iphdr *ip = (struct iphdr *)(BPF_CORE_READ(skb, data) + 14);
        struct tcphdr *tcp = (struct tcphdr *)(BPF_CORE_READ(skb, data) +
                                               sizeof(struct iphdr) + 14);
        struct packet_tuple pkt_tuple = {};
        get_pkt_tuple(&pkt_tuple, ip, tcp);

        // FILTER_DPORT
        // FILTER_SPORT

        struct ktime_info *tinfo, zero = {};

        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple, &zero);
        if (tinfo == NULL) {
            bpf_printk("v4 rx tinfo init fail.\n");
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns() / 1000;
        bpf_printk("v4 rx init.\n");
    } else if (protocol == __bpf_htons(ETH_P_IPV6)) { // Protocol is IPV6
        struct ipv6hdr *ip6h =
            (struct ipv6hdr *)(BPF_CORE_READ(skb, data) + 14);
        struct tcphdr *tcp = (struct tcphdr *)(BPF_CORE_READ(skb, data) +
                                               sizeof(struct ipv6hdr) + 14);
        struct packet_tuple pkt_tuple = {};
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

        // FILTER_DPORT
        // FILTER_SPORT

        struct ktime_info *tinfo, zero = {};

        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple, &zero);
        if (tinfo == NULL) {
            bpf_printk("v6 rx tinfo init fail.\n");
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns() / 1000;
        bpf_printk("v6 rx init.\n");
    }
    return 0;
}

/** in only ipv4 */
SEC("kprobe/ip_rcv_core")
int BPF_KPROBE(ip_rcv_core, struct sk_buff *skb) {

    if (skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    // FILTER_DPORT
    // FILTER_SPORT

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->ip_time = bpf_ktime_get_ns() / 1000;
    bpf_printk("rx enter ipv4 layer.\n");
    return 0;
}

/** in only ipv6 */
SEC("kprobe/ip6_rcv_core")
int BPF_KPROBE(ip6_rcv_core, struct sk_buff *skb) {

    if (skb == NULL)
        return 0;
    struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

    // FILTER_DPORT
    // FILTER_SPORT

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->ip_time = bpf_ktime_get_ns() / 1000;
    bpf_printk("rx enter ipv6 layer.\n");
    return 0;
}

/**in only ipv4 */
SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv, struct sk_buff *skb) {

    if (skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    // FILTER_DPORT
    // FILTER_SPORT

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->tcp_time = bpf_ktime_get_ns() / 1000;
    bpf_printk("rx enter tcp4 layer.\n");
    return 0;
}

/** in only ipv6 */
SEC("kprobe/tcp_v6_rcv")
int BPF_KPROBE(tcp_v6_rcv, struct sk_buff *skb) {

    if (skb == NULL)
        return 0;
    struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

    // FILTER_DPORT
    // FILTER_SPORT

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->tcp_time = bpf_ktime_get_ns() / 1000;
    bpf_printk("rx enter tcp6 layer.\n");
    return 0;
}

// v4 & v6 do_rcv to get sk and other info
SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb) {

    if (sk == NULL || skb == NULL)
        return 0;
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        bpf_printk("get a v4 rx pack but conn not record, its sock is: %p", sk);
        return 0;
    }
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->sk = sk;
    // copy comm string
    for (int i = 0; i < MAX_COMM; ++i) {
        tinfo->comm[i] = conn->comm[i];
    }
    bpf_printk("rx enter tcp4_do_rcv, sk: %p \n", sk);
    // conn info update
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    conn->srtt = BPF_CORE_READ(tp, srtt_us);
    conn->duration = bpf_ktime_get_ns() / 1000 - conn->init_timestamp;
    conn->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
    conn->bytes_received = BPF_CORE_READ(tp, bytes_received);
    conn->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
    conn->snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
    conn->sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
    conn->sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
    conn->tcp_backlog = BPF_CORE_READ(sk, sk_ack_backlog);
    conn->max_tcp_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);
    return 0;
}
SEC("kprobe/tcp_v6_do_rcv")
int BPF_KPROBE(tcp_v6_do_rcv, struct sock *sk, struct sk_buff *skb) {
    if (sk == NULL || skb == NULL)
        return 0;
    bpf_printk("rx enter tcp6_do_rcv. \n");
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        bpf_printk("get a v6 rx pack but conn not record, its sock is: %p", sk);
        return 0;
    }

    struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->sk = sk;

    for (int i = 0; i < MAX_COMM; ++i) {
        tinfo->comm[i] = conn->comm[i];
    }
    bpf_printk("rx enter tcp6_do_rcv, sk: %p \n", sk);
    /*----- update conn info ------*/
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    conn->srtt = BPF_CORE_READ(tp, srtt_us);
    conn->duration = bpf_ktime_get_ns() / 1000 - conn->init_timestamp;
    conn->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
    conn->bytes_received = BPF_CORE_READ(tp, bytes_received);
    conn->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
    conn->snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
    conn->sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
    conn->sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
    conn->tcp_backlog = BPF_CORE_READ(sk, sk_ack_backlog);
    conn->max_tcp_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);

    return 0;
}

/** in ipv4 && ipv6 */
SEC("kprobe/skb_copy_datagram_iter")
int BPF_KPROBE(skb_copy_datagram_iter, struct sk_buff *skb) {
    __be16 protocol = BPF_CORE_READ(skb, protocol);

    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    struct ktime_info *tinfo;
    if (protocol == __bpf_htons(ETH_P_IP)) { /** ipv4 */
        if (skb == NULL)
            return 0;
        struct iphdr *ip = skb_to_iphdr(skb);
        get_pkt_tuple(&pkt_tuple, ip, tcp);

        // FILTER_DPORT
        // FILTER_SPORT

        tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
        if (tinfo == NULL) {
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
    bpf_printk("rx enter app layer.\n");
    struct pack_t *packet;
    packet = bpf_ringbuf_reserve(&rb, sizeof(*packet), 0);
    if (!packet) {
        return 0;
    }
    bpf_printk("rx packet sk: %p\n", sk);
    for (int i = 0; i < MAX_COMM; ++i) {
        packet->comm[i] = tinfo->comm[i];
    }

    packet->sock = sk;
    packet->ack = pkt_tuple.ack;
    packet->seq = pkt_tuple.seq;
    packet->mac_time = tinfo->ip_time - tinfo->mac_time;
    packet->ip_time = tinfo->tcp_time - tinfo->ip_time;
    packet->tcp_time = tinfo->app_time - tinfo->tcp_time;
    packet->rx = 1;
    bpf_ringbuf_submit(packet, 0);
    return 0;
}

/***************************************** end of receive path
 * ****************************************/

/************************************************ send path
 * *******************************************/
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
    struct ktime_info *tinfo, zero = {};
    struct packet_tuple pkt_tuple = {};
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

        // FILTER_DPORT
        // FILTER_SPORT

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

        // FILTER_DPORT
        // FILTER_SPORT

        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(
            &timestamps, &pkt_tuple, &zero);
        if (tinfo == NULL) {
            return 0;
        }
        tinfo->tcp_time = bpf_ktime_get_ns() / 1000;
    }
    for (int i = 0; i < MAX_COMM; ++i) {
        tinfo->comm[i] = conn->comm[i];
    }
    tinfo->sk = sk;
    /*----- update conn info ------*/
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    conn->srtt = BPF_CORE_READ(tp, srtt_us);
    conn->duration = bpf_ktime_get_ns() / 1000 - conn->init_timestamp;
    conn->bytes_acked = BPF_CORE_READ(tp, bytes_acked);
    conn->bytes_received = BPF_CORE_READ(tp, bytes_received);
    conn->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);
    conn->snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);
    conn->sndbuf = BPF_CORE_READ(sk, sk_sndbuf);
    conn->sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);
    conn->tcp_backlog = BPF_CORE_READ(sk, sk_ack_backlog);
    conn->max_tcp_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);
    return 0;
}

/*!
* \brief: 获取数据包进入IP层时刻的时间戳
* tips:   此时ip数据段还没有数据，不能用 get_pkt_tuple(&pkt_tuple, ip,
tcp)获取ip段的数据 out only ipv4
*/
SEC("kprobe/ip_queue_xmit")
int BPF_KPROBE(ip_queue_xmit, struct sock *sk, struct sk_buff *skb) {
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AF_INET) {
        struct packet_tuple pkt_tuple = {};
        struct tcphdr *tcp = skb_to_tcphdr(skb);
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

        // FILTER_DPORT
        // FILTER_SPORT

        struct ktime_info *tinfo;
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
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family == AF_INET6) {
        struct packet_tuple pkt_tuple = {};
        struct tcphdr *tcp = skb_to_tcphdr(skb);
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

        // FILTER_DPORT
        // FILTER_SPORT

        struct ktime_info *tinfo;
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
    const struct ethhdr *eth = (struct ethhdr *)BPF_CORE_READ(skb, data);
    u16 protocol = BPF_CORE_READ(eth, h_proto);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
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

        // FILTER_DPORT
        // FILTER_SPORT

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
    struct packet_tuple pkt_tuple = {};
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
        tinfo->qdisc_time = bpf_ktime_get_ns() / 1000;
    } else if (protocol == __bpf_ntohs(ETH_P_IPV6)) {
        /** ipv6 */
        struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

        // FILTER_DPORT
        // FILTER_SPORT

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
    struct pack_t *packet;
    packet = bpf_ringbuf_reserve(&rb, sizeof(*packet), 0);
    if (!packet) {
        return 0;
    }
    for (int i = 0; i < MAX_COMM; ++i) {
        packet->comm[i] = tinfo->comm[i];
    }
    bpf_printk("tx packet sk: %p\n", sk);
    packet->sock = sk;
    packet->ack = pkt_tuple.ack;
    packet->seq = pkt_tuple.seq;
    packet->tcp_time = tinfo->ip_time - tinfo->tcp_time;
    packet->ip_time = tinfo->mac_time - tinfo->ip_time;
    packet->mac_time = tinfo->qdisc_time - tinfo->mac_time;
    packet->rx = 0;
    bpf_ringbuf_submit(packet, 0);

    return 0;
};
