/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <linux/bpf.h>
#include <linux/if_ether.h>

typedef __u32 xdp_act;


#define MAX_RULES 256


//#define DEBUG_PRINT
//#define DEBUG_PRINT_EVERY

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

// 转发表项
struct rt_item {
	__u32 saddr;
	__u8 eth_source[ETH_ALEN]; // 封装帧的源MAC地址。
	__u8 eth_dest[ETH_ALEN]; // 封装帧的目标MAC地址。
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
