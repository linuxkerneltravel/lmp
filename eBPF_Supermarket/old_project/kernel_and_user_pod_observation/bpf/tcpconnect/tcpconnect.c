// +build ignore

// ver: 1e510db2fe3a134c476f582defc3c68e71e68b1b
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
BPF_HASH(currsock, u32, struct sock *);
// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_ns;
    u32 pid;
    u32 tid;
    u32 saddr;
    u32 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
	u32 pad;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);
struct ipv6_data_t {
    u64 ts_ns;
    u32 pid;
    u32 tid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ip;
    u16 lport;
    u16 dport;
	u32 pad;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    // if (container_should_be_filtered()) {
    //     return 0;
    // }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    /*FILTER_PID*/

    // stash the sock ptr for lookup on return
    currsock.update(&tid, &sk);
    return 0;
};

static int trace_connect_return(struct pt_regs *ctx, short family)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    struct sock **skpp;
    skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        return 0;   // missed entry
    }
    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&tid);
        return 0;
    }
    // pull in details
    struct sock *skp = *skpp;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;

    /*FILTER_PORT*/
    /*FILTER_FAMILY*/
    if (family == 4) {
        struct ipv4_data_t data4 = {.pid = pid, .ip = family};
        data4.tid = tid;
	    data4.ts_ns = bpf_ktime_get_ns();
	    data4.saddr = skp->__sk_common.skc_rcv_saddr;
	    data4.daddr = skp->__sk_common.skc_daddr;
	    data4.lport = lport;
	    data4.dport = ntohs(dport);
	    bpf_get_current_comm(&data4.task, sizeof(data4.task));
	    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else /* 6 */ {
	    struct ipv6_data_t data6 = {.pid = pid, .ip = family};
        data6.tid = tid;
	    data6.ts_ns = bpf_ktime_get_ns();
	    bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	    bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	    data6.lport = lport;
	    data6.dport = ntohs(dport);
	    bpf_get_current_comm(&data6.task, sizeof(data6.task));
	    ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    currsock.delete(&tid);
    return 0;
}
int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}
int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}
