#include "tcpwatch.h"
#include "vmlinux.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN);
    __type(key, struct sock *);
    __type(value, struct packs_lru_buf_t); // fd of map
} packets_info SEC(".maps");

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

    conn.init_timestamp = bpf_ktime_get_ns();
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
        bpf_printk("tcp_v4_connect_exit but ret error\n");
        bpf_map_delete_elem(&sock_stores, &pid);
        return 0;
    }
    struct sock *sk = *skp;
    struct conn_t conn = {};
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
    bpf_printk("tcp_v4_connect_exit update sk: %p.\n", sk);
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
        bpf_printk("tcp_v6_connect_exit but return err\n");
        bpf_map_delete_elem(&sock_stores, &pid);
        return 0;
    }
    struct sock *sk = *skp;
    struct conn_t conn = {};
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

    return 0;
}

/* TCP State */
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state, struct sock *sk, int state) {
    struct conn_t *value = bpf_map_lookup_elem(&conns_info, &sk);
    if (state == TCP_CLOSE && value) {
        // delete
        bpf_map_delete_elem(&sock_stores, &value->ptid);
        bpf_map_delete_elem(&conns_info, &sk);
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

    if (protocol == __bpf_ntohs(ETH_P_IP)) { // Protocol is IP
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
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns() / 1000;
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
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns();
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
    if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
        return 0;
    }
    tinfo->ip_time = bpf_ktime_get_ns();

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
    if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
        return 0;
    }
    tinfo->ip_time = bpf_ktime_get_ns();

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
    if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
        return 0;
    }
    tinfo->tcp_time = bpf_ktime_get_ns();

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
    if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
        return 0;
    }
    tinfo->tcp_time = bpf_ktime_get_ns();

    return 0;
}

// v4 & v6 do_rcv to get sk and other info

/** in ipv4 && ipv6 */
SEC("kprobe/skb_copy_datagram_iter")
int BPF_KPROBE(skb_copy_datagram_iter, struct sk_buff *skb) {
    const struct ethhdr *eth = (struct ethhdr *)BPF_CORE_READ(skb, data);
    u16 protocol = BPF_CORE_READ(eth, h_proto);

    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    struct ktime_info *tinfo;

    if (protocol == __bpf_ntohs(ETH_P_IP)) { /** ipv4 */
        if (skb == NULL)
            return 0;
        struct iphdr *ip = skb_to_iphdr(skb);
        get_pkt_tuple(&pkt_tuple, ip, tcp);

        // FILTER_DPORT
        // FILTER_SPORT

        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        tinfo->app_time = bpf_ktime_get_ns();
    } else if (protocol == __bpf_htons(ETH_P_IPV6)) {
        if (skb == NULL)
            return 0;
        struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

        // FILTER_DPORT
        // FILTER_SPORT

        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        tinfo->app_time = bpf_ktime_get_ns();
    }

    return 0;
}

/***************************************** end of receive path
 * ****************************************/

// SRTT tcp_ack

/************************************************ send path
 * *******************************************/
/*!
 * \brief: 获取数据包进入TCP层时刻的时间戳, 发送tcp层起始点
 *         out ipv4 && ipv6
 */
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {

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
        tinfo->tcp_time = bpf_ktime_get_ns();
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
        tinfo->tcp_time = bpf_ktime_get_ns();
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
            // debug info look : cat
            // /sys/kernel/debug/tracing/trace_pipe, root mode
            __bpf_printk("Hash search failed, please check!\n");
            return 0;
        }
        tinfo->ip_time = bpf_ktime_get_ns();
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
            // debug info look : cat
            // /sys/kernel/debug/tracing/trace_pipe, root mode
            __bpf_printk("Hash search failed, please check!\n");
            return 0;
        }
        tinfo->ip_time = bpf_ktime_get_ns();
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
        tinfo->mac_time = bpf_ktime_get_ns();
    } else if (protocol == __bpf_ntohs(ETH_P_IPV6)) {
        /** ipv6 */
        struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

        // FILTER_DPORT
        // FILTER_SPORT

        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns();
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
        tinfo->qdisc_time = bpf_ktime_get_ns();
    } else if (protocol == __bpf_ntohs(ETH_P_IPV6)) {
        /** ipv6 */
        struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);

        // FILTER_DPORT
        // FILTER_SPORT

        if ((tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple)) == NULL) {
            return 0;
        }
        tinfo->qdisc_time = bpf_ktime_get_ns();
    }
    u16 nat_sport = 0;
    nat_sport = BPF_CORE_READ(tcp, source);

    return 0;
};