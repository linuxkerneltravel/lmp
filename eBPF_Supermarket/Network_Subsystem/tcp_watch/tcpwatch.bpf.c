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

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb) {
    return (struct tcphdr *)((BPF_CORE_READ(skb, head) +
                              BPF_CORE_READ(skb, transport_header)));
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