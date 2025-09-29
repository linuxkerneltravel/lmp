#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "tcplife.h"


#define MAX_ENTRIES	10240
#define AF_INET		2
#define AF_INET6	10

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, __u64);
} birth SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct sock *);
	__type(value, struct ident);
} idents SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");


SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *args)
{
	__u64 ts, *start, delta_us, rx_b, tx_b;
	struct ident ident = {}, *identp;
	__u16 sport, dport, family;
	struct event event = {};
	struct tcp_sock *tp;
	struct sock *sk;
	__u32 pid;

	if (BPF_CORE_READ(args, protocol) != IPPROTO_TCP)
		return 0;

	family = BPF_CORE_READ(args, family);
	sport = BPF_CORE_READ(args, sport);
	dport = BPF_CORE_READ(args, dport);
	sk = (struct sock *)BPF_CORE_READ(args, skaddr);

	/* 记录连接开始时间 */
	if (BPF_CORE_READ(args, newstate) < TCP_FIN_WAIT1) {
		ts = bpf_ktime_get_ns();
		bpf_map_update_elem(&birth, &sk, &ts, BPF_ANY);
	}

	/* 保存 PID + COMM 信息 */
	if (BPF_CORE_READ(args, newstate) == TCP_SYN_SENT || 
	    BPF_CORE_READ(args, newstate) == TCP_LAST_ACK) {
		pid = bpf_get_current_pid_tgid() >> 32;
		ident.pid = pid;
		bpf_get_current_comm(ident.comm, sizeof(ident.comm));
		bpf_map_update_elem(&idents, &sk, &ident, BPF_ANY);
	}

	/* 只在连接关闭时输出事件 */
	if (BPF_CORE_READ(args, newstate) != TCP_CLOSE)
		return 0;

	start = bpf_map_lookup_elem(&birth, &sk);
	if (!start) {
		bpf_map_delete_elem(&idents, &sk);
		return 0;
	}
	ts = bpf_ktime_get_ns();
	delta_us = (ts - *start) / 1000;

	identp = bpf_map_lookup_elem(&idents, &sk);
	pid = identp ? identp->pid : (bpf_get_current_pid_tgid() >> 32);

	tp = (struct tcp_sock *)sk;
	rx_b = BPF_CORE_READ(tp, bytes_received);
	tx_b = BPF_CORE_READ(tp, bytes_acked);

	event.ts_us = ts / 1000;
	event.span_us = delta_us;
	event.rx_b = rx_b;
	event.tx_b = tx_b;
	event.pid = pid;
	event.sport = sport;
	event.dport = dport;
	event.family = family;
	if (!identp)
		bpf_get_current_comm(event.comm, sizeof(event.comm));
	else
		bpf_probe_read_kernel(event.comm, sizeof(event.comm), (void *)identp->comm);

	if (family == AF_INET) {
		bpf_probe_read_kernel(&event.saddr, sizeof(args->saddr), BPF_CORE_READ(args, saddr));
		bpf_probe_read_kernel(&event.daddr, sizeof(args->daddr), BPF_CORE_READ(args, daddr));
	} else {	/* AF_INET6 */
		bpf_probe_read_kernel(&event.saddr, sizeof(args->saddr_v6), BPF_CORE_READ(args, saddr_v6));
		bpf_probe_read_kernel(&event.daddr, sizeof(args->daddr_v6), BPF_CORE_READ(args, daddr_v6));
	}

	bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	/* 清理 */
	bpf_map_delete_elem(&birth, &sk);
	bpf_map_delete_elem(&idents, &sk);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
