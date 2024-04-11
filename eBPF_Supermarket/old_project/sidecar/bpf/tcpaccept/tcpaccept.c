// +build ignore

// ver: 28955512d991ee3849c2a9accfc54bef9cd35f21
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
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

// The following code uses kprobes to instrument inet_csk_accept().
// On Linux 4.16 and later, we could use sock:inet_sock_set_state
// tracepoint for efficiency, but it may output wrong PIDs. This is
// because sock:inet_sock_set_state may run outside of process context.
// Hence, we stick to kprobes until we find a proper solution.

int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
	//if (container_should_be_filtered()) {
	//    return 0;
	//}
	struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;

	/*FILTER_PID*/

	if (newsk == NULL)
	  return 0;
	// check this is TCP
	u16 protocol = 0;
	// workaround for reading the sk_protocol bitfield:
	// Following comments add by Joe Yin:
	// Unfortunately,it can not work since Linux 4.10,
	// because the sk_wmem_queued is not following the bitfield of sk_protocol.
	// And the following member is sk_gso_max_segs.
	// So, we can use this:
	// bpf_probe_read_kernel(&protocol, 1, (void *)((u64)&newsk->sk_gso_max_segs) - 3);
	// In order to  diff the pre-4.10 and 4.10+ ,introduce the variables gso_max_segs_offset,sk_lingertime,
	// sk_lingertime is closed to the gso_max_segs_offset,and
	// the offset between the two members is 4
	int gso_max_segs_offset = offsetof(struct sock, sk_gso_max_segs);
	int sk_lingertime_offset = offsetof(struct sock, sk_lingertime);
	// Since kernel v5.6 sk_protocol is its own u16 field and gso_max_segs
	// precedes sk_lingertime.
	if (sk_lingertime_offset - gso_max_segs_offset == 2)
		protocol = newsk->sk_protocol;
	else if (sk_lingertime_offset - gso_max_segs_offset == 4)
		// 4.10+ with little endian
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 3);
	else
		// pre-4.10 with little endian
		protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 3);
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		// 4.10+ with big endian
		protocol = *(u8 *)((u64)&newsk->sk_gso_max_segs - 1);
	else
		// pre-4.10 with big endian
		protocol = *(u8 *)((u64)&newsk->sk_wmem_queued - 1);
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
	if (protocol != IPPROTO_TCP)
		return 0;
	// pull in details
	u16 family = 0, lport = 0, dport;
	family = newsk->__sk_common.skc_family;
	lport = newsk->__sk_common.skc_num;
	dport = newsk->__sk_common.skc_dport;
	dport = ntohs(dport);

	/*FILTER_FAMILY*/
	/*FILTER_PORT*/

	if (family == AF_INET) {
		struct ipv4_data_t data4 = {.pid = pid, .ip = 4};
		data4.tid = tid;
		data4.ts_ns = bpf_ktime_get_ns();
		data4.saddr = newsk->__sk_common.skc_rcv_saddr;
		data4.daddr = newsk->__sk_common.skc_daddr;
		data4.lport = lport;
		data4.dport = dport;
		bpf_get_current_comm(&data4.task, sizeof(data4.task));
		ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
	} else if (family == AF_INET6) {
		struct ipv6_data_t data6 = {.pid = pid, .ip = 6};
		data6.tid = tid;
		data6.ts_ns = bpf_ktime_get_ns();
		bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		data6.lport = lport;
		data6.dport = dport;
		bpf_get_current_comm(&data6.task, sizeof(data6.task));
		ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
	}
	// else drop
	return 0;
}