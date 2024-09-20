/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <linux/bpf.h>

typedef __u32 xdp_act;
#define ETH_ALEN 6

#define ALERT_ERR_STR "[XACL] ERROR:"


#define MAX_RULES 256


#ifndef PATH_MAX
#define PATH_MAX	4096
#endif


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

struct conn_mac {
	unsigned char dest[ETH_ALEN];
	unsigned char source[ETH_ALEN];
};

struct rules_mac {
	unsigned char dest[ETH_ALEN];
	unsigned char source[ETH_ALEN];
	__u16 action;
	__u16 prev_rule;
	__u16 next_rule;
};
// 转发表项
struct rt_item {
	__u32 saddr;
	__u8 eth_source[ETH_ALEN]; // 封装帧的源MAC地址。
	__u8 eth_dest[ETH_ALEN]; // 封装帧的目标MAC地址。
};

// mac 过滤
struct mac_addr {
    __u8 addr[ETH_ALEN];
};


// 会话保持
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
