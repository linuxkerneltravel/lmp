#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char task[TASK_COMM_LEN];
};
BPF_HASH(ipv4_send, struct ipv4_data_t);
BPF_HASH(ipv4_recv, struct ipv4_data_t);

struct ipv6_data_t {
    u32 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u64 __pad__;
    char task[TASK_COMM_LEN];
};


BPF_HASH(ipv6_send, struct ipv6_data_t);
BPF_HASH(ipv6_recv, struct ipv6_data_t);
BPF_HASH(sock_store, u32, struct sock *);

static int tcp_sendstat(int size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    ##FILTER_PID##

    struct sock **skpp;
    skpp = sock_store.lookup(&pid);
    if (skpp == 0) {
        return 0; //miss the entry
    }

    // !!!! please use bpf_probe_read_kernel to read any data from skp !!!! //

    struct sock *skp = *skpp;
    u16 family, dport;
    bpf_probe_read_kernel(&family, sizeof(family), &skp->__sk_common.skc_family);
    ##FILTER_FAMILY##
    bpf_probe_read_kernel(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
    
    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = pid};
        bpf_probe_read_kernel(&data4.saddr, sizeof(data4.saddr), &skp->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&data4.daddr, sizeof(data4.daddr), &skp->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&data4.sport, sizeof(data4.sport), &skp->__sk_common.skc_num);
        data4.dport = ntohs(dport); 
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_send.increment(data4, size);

    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid};
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.sport, sizeof(data6.sport), &skp->__sk_common.skc_num);
        data6.dport = ntohs(dport); 
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_send.increment(data6, size);
    }
    sock_store.delete(&pid);

    return 0;
}

int kretprobe__tcp_sendmsg(struct pt_regs *ctx) {
    int size = PT_REGS_RC(ctx);
    if (size > 0)
        return tcp_sendstat(size);
    else
        return 0;
}

int kretprobe__tcp_sendpage(struct pt_regs *ctx) {
    int size = PT_REGS_RC(ctx);
    if (size > 0)
        return tcp_sendstat(size);
    else
        return 0;
}

static int tcp_send_entry(struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    ##FILTER_PID##
    u16 family = sk->__sk_common.skc_family;
    ##FILTER_FAMILY##
    sock_store.update(&pid, &sk);
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    return tcp_send_entry(sk);
}

int kprobe__tcp_sendpage(struct pt_regs *ctx, struct sock *sk, struct page *page, int offset, size_t size) {
    return tcp_send_entry(sk);
}
/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    ##FILTER_PID##

    u16 family = sk->__sk_common.skc_family;
    ##FILTER_FAMILY##
    u16 sport = sk->__sk_common.skc_num;
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);

    if (copied <= 0)
        return 0;

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = pid};
        data4.saddr = sk->__sk_common.skc_rcv_saddr;
        data4.daddr = sk->__sk_common.skc_daddr;
        data4.sport = sport;
        data4.dport = dport;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_recv.increment(data4, copied);

    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid};
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        data6.sport = sport;
        data6.dport = dport;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_recv.increment(data6, copied);
    }

    return 0;
}
