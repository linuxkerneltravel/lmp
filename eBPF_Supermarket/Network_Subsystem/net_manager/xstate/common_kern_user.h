/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <linux/bpf.h>

#define MAX_CONNS 0XFFFFF

//#define DEBUG_PRINT
//#define DEBUG_PRINT_EVERY

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct conn_ipv4_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 proto;
};

struct conn_ipv4_val {
	__u32 tcp_state;
	__u32 rid;
};

enum {
	TCP_S_NONE = 0U,
	TCP_S_ESTABLISHED,
	TCP_S_SYN_SENT,
	TCP_S_SYN_RECV,
	TCP_S_FIN_WAIT1,
	TCP_S_FIN_WAIT2,
	TCP_S_CLOSE_WAIT,
	TCP_S_CLOSE,
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
