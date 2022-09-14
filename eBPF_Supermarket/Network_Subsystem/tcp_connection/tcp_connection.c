#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 ip;
    u8 direction; // 0-accept, 1-connect
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ts_us;
    u32 pid;
    u16 sport;
    u16 dport;
    u8 ip;
    u8 direction;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

int kretprobe__inet_csk_accept(struct pt_regs *ctx){
    
    ##FILTER_DIRECTION##

    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    ##FILTER_PID##

    if (newsk == NULL)
        return 0;

    // check this is TCP
    u16 protocol = newsk->sk_protocol;
    if (protocol != IPPROTO_TCP)
        return 0;

    // pull in details
    u16 family, dport;
    bpf_probe_read_kernel(&family, sizeof(family), &newsk->__sk_common.skc_family);
    ##FILTER_FAMILY##
    bpf_probe_read_kernel(&dport, sizeof(dport),&newsk->__sk_common.skc_dport);

    ##FILTER_PORT##

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = 4};
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data4.saddr, sizeof(data4.saddr), &newsk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&data4.daddr, sizeof(data4.daddr), &newsk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&data4.sport, sizeof(data4.sport), &newsk->__sk_common.skc_num);
        data4.dport = ntohs(dport);;
        data4.direction = 0;
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid, .ip = 6};
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.sport, sizeof(data6.sport), &newsk->__sk_common.skc_num);
        data6.dport = ntohs(dport);;
        data6.direction = 0;
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

    return 0;
}


BPF_HASH(sock_stores, u32, struct sock *);


int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    ##FILTER_FAMILY6##
    ##FILTER_DIRECTION##

	u32 pid = bpf_get_current_pid_tgid();
    ##FILTER_PID##

	// stash the sock ptr for lookup on return
	sock_stores.update(&pid, &sk);
	return 0;
};


int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    ##FILTER_FAMILY6##
    ##FILTER_DIRECTION##

	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

    ##FILTER_PID##

	struct sock **skpp;
	skpp = sock_stores.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret != 0) {
		sock_stores.delete(&pid);
		return 0;
	}

    // pull in details
    struct sock *skp = *skpp;
    u16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

    ##FILTER_PORT##

    struct ipv4_data_t data4 = {.pid = pid, .ip = 4};
    data4.ts_us = bpf_ktime_get_ns() / 1000;
    bpf_probe_read_kernel(&data4.saddr, sizeof(data4.saddr), &skp->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&data4.daddr, sizeof(data4.daddr), &skp->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&data4.sport, sizeof(data4.sport), &skp->__sk_common.skc_num);
    data4.dport = ntohs(dport);
    data4.direction = 1;
    bpf_get_current_comm(&data4.task, sizeof(data4.task));
    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

	sock_stores.delete(&pid);

	return 0;
}



int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) {
    ##FILTER_FAMILY4##
    ##FILTER_DIRECTION##

	u32 pid = bpf_get_current_pid_tgid();
    ##FILTER_PID##

	// stash the sock ptr for lookup on return
	sock_stores.update(&pid, &sk);
	return 0;
};

int kretprobe__tcp_v6_connect(struct pt_regs *ctx) {
    ##FILTER_FAMILY4##
    ##FILTER_DIRECTION##

    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid();

    ##FILTER_PID##

    struct sock **skpp;
    skpp = sock_stores.lookup(&pid);
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0) {
        sock_stores.delete(&pid);
        return 0;
    }

    // pull in details
    struct sock *skp = *skpp;
    u16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport), &skp->__sk_common.skc_dport);

    ##FILTER_PORT##

    struct ipv6_data_t data6 = {.pid = pid, .ip = 6};
    data6.ts_us = bpf_ktime_get_ns() / 1000;
    bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&data6.sport, sizeof(data6.sport), &skp->__sk_common.skc_num);
    data6.dport = ntohs(dport);
    data6.direction = 1;
    bpf_get_current_comm(&data6.task, sizeof(data6.task));
    ipv6_events.perf_submit(ctx, &data6, sizeof(data6));

    sock_stores.delete(&pid);

    return 0;
}
