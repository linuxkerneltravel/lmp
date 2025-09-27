#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

#define TASK_COMM_LEN 16

struct event {
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	char comm[TASK_COMM_LEN];
	__u64 ts_us;
	__u64 delta_us;
	__u32 tgid;
	__u16 lport;
	__u16 dport;
	__u32 af; // AF_INET or AF_INET6
};

#endif /* __TCPCONNLAT_H */ 