#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <bcc/proto.h>
struct ipv4_data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u8 ip;
    u16 dport;
    u16 sport;
    char task[TASK_COMM_LEN];
    u32 srtt;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u8 ip;
    u16 dport;
    u16 sport;
    char task[TASK_COMM_LEN];
    u32 srtt;
};
BPF_PERF_OUTPUT(ipv6_events);

BPF_HASH(tmp, u64, struct sock *);

int trace_tcp_ack_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid = bpf_get_current_pid_tgid();
    tmp.update(&pid, &sk);
    return 0;
}

int trace_tcp_ack_return(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	if (ret != 1)
	    return 0;

        u64 pid = bpf_get_current_pid_tgid();
        struct sock **skp;
        skp = tmp.lookup(&pid);
        if (skp == 0)
            return 0;
        tmp.delete(&pid);

        struct sock *sk = *skp;
	if (sk->__sk_common.skc_state != TCP_ESTABLISHED)
            return 0;

	struct tcp_sock *tp = (struct tcp_sock *)sk;
	u32 srtt = (tp->srtt_us >> 3);
	FILTER {
		u32 pid_t = pid >> 32;
		u16 dport = sk->__sk_common.skc_dport;
		u16 sport = sk->__sk_common.skc_num;
		u16 family = sk->__sk_common.skc_family;
		if (family == AF_INET) {
			struct ipv4_data_t data4 = {.pid = pid_t, .ip = 4, .srtt = srtt};
			bpf_get_current_comm(&data4.task, sizeof(data4.task));
			data4.saddr = sk->__sk_common.skc_rcv_saddr;
			data4.daddr = sk->__sk_common.skc_daddr;
			data4.sport = sport;
			data4.dport = ntohs(dport);
			ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
		} else {
			struct ipv6_data_t data6 = {.pid = pid_t, .ip = 6, .srtt = srtt};
			bpf_get_current_comm(&data6.task, sizeof(data6.task));
			bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
								  sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
			bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
								  sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
			data6.sport = sport;
			data6.dport = ntohs(dport);
			ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
		}
	}

	return 0;
}