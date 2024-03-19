/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <linux/bpf.h>

typedef __u32 xdp_act;

#define ALERT_ERR_STR "[XACL] ERROR:"

//#define KERNEL_5_17
#define KERNEL_5_10

#ifdef KERNEL_5_10
#define MAX_RULES 256
#endif

#ifdef KERNEL_5_17
#define MAX_RULES 0XFFFF
#endif

//#define DEBUG_PRINT
//#define DEBUG_PRINT_EVERY

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct conn_ipv4 {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u16 ip_proto;
};

struct rules_ipv4 {
	__u32 saddr;
	__u32 daddr;
	__u8  saddr_mask;
	__u8  daddr_mask;
	__u16 sport;
	__u16 dport;
	__u16 ip_proto;
	__u16 action;
	__u16 prev_rule;
	__u16 next_rule;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
