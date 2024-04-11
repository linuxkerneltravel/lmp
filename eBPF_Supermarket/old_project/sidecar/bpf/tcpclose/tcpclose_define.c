// +build ignore

// ver: 9d06ced06f63161570d5fb6376acf099225899a3
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>
BPF_HASH(birth, struct sock *, u64);
// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_ns;
    u32 pid;
	u32 tid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
	u32 pad;
    u64 rx_b;
    u64 tx_b;
    u64 span_ns;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);
struct ipv6_data_t {
    u64 ts_ns;
    u32 pid;
	u32 tid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
	u32 pad;
    u64 rx_b;
    u64 tx_b;
    u64 span_ns;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);
struct id_t {
    u32 pid;
	u32 tid;
    char task[TASK_COMM_LEN];
};
BPF_HASH(whoami, struct sock *, struct id_t);
