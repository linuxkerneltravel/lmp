/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#include <linux/bpf.h>

typedef __u32 xdp_act;


#define MAX_RULES 1024

struct key_mac {
	__u8 src_mac[6];
};

struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};



#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* __COMMON_KERN_USER_H */
