#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;

typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef s32 int32_t;
typedef u32 uint32_t;
typedef __u32 __wsum;

enum bpf_map_type {
        BPF_MAP_TYPE_UNSPEC = 0,
        BPF_MAP_TYPE_HASH = 1,
        BPF_MAP_TYPE_ARRAY = 2,
        BPF_MAP_TYPE_PROG_ARRAY = 3,
        BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
        BPF_MAP_TYPE_PERCPU_HASH = 5,
        BPF_MAP_TYPE_PERCPU_ARRAY = 6,
        BPF_MAP_TYPE_STACK_TRACE = 7,
        BPF_MAP_TYPE_CGROUP_ARRAY = 8,
        BPF_MAP_TYPE_LRU_HASH = 9,
        BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
        BPF_MAP_TYPE_LPM_TRIE = 11,
        BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
        BPF_MAP_TYPE_HASH_OF_MAPS = 13,
        BPF_MAP_TYPE_DEVMAP = 14,
        BPF_MAP_TYPE_SOCKMAP = 15,
        BPF_MAP_TYPE_CPUMAP = 16,
        BPF_MAP_TYPE_XSKMAP = 17,
        BPF_MAP_TYPE_SOCKHASH = 18,
        BPF_MAP_TYPE_CGROUP_STORAGE = 19,
        BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
        BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
        BPF_MAP_TYPE_QUEUE = 22,
        BPF_MAP_TYPE_STACK = 23,
        BPF_MAP_TYPE_SK_STORAGE = 24,
        BPF_MAP_TYPE_DEVMAP_HASH = 25,
        BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
        BPF_MAP_TYPE_INODE_STORAGE = 28,
        BPF_MAP_TYPE_TASK_STORAGE = 29,
};

enum sk_action {
        SK_DROP = 0,
        SK_PASS = 1,
};

enum {
        BPF_ANY = 0,
        BPF_NOEXIST = 1,
        BPF_EXIST = 2,
        BPF_F_LOCK = 4,
};

enum {
        BPF_F_INGRESS = 1,
};

enum {
        BPF_SOCK_OPS_RTO_CB_FLAG = 1,
        BPF_SOCK_OPS_RETRANS_CB_FLAG = 2,
        BPF_SOCK_OPS_STATE_CB_FLAG = 4,
        BPF_SOCK_OPS_RTT_CB_FLAG = 8,
        BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG = 16,
        BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG = 32,
        BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG = 64,
        BPF_SOCK_OPS_ALL_CB_FLAGS = 127,
};

enum {
        BPF_SOCK_OPS_VOID = 0,
        BPF_SOCK_OPS_TIMEOUT_INIT = 1,
        BPF_SOCK_OPS_RWND_INIT = 2,
        BPF_SOCK_OPS_TCP_CONNECT_CB = 3,
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB = 4,
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB = 5,
        BPF_SOCK_OPS_NEEDS_ECN = 6,
        BPF_SOCK_OPS_BASE_RTT = 7,
        BPF_SOCK_OPS_RTO_CB = 8,
        BPF_SOCK_OPS_RETRANS_CB = 9,
        BPF_SOCK_OPS_STATE_CB = 10,
        BPF_SOCK_OPS_TCP_LISTEN_CB = 11,
        BPF_SOCK_OPS_RTT_CB = 12,
        BPF_SOCK_OPS_PARSE_HDR_OPT_CB = 13,
        BPF_SOCK_OPS_HDR_OPT_LEN_CB = 14,
        BPF_SOCK_OPS_WRITE_HDR_OPT_CB = 15,
};

enum {
        BPF_TCP_ESTABLISHED = 1,
        BPF_TCP_SYN_SENT = 2,
        BPF_TCP_SYN_RECV = 3,
        BPF_TCP_FIN_WAIT1 = 4,
        BPF_TCP_FIN_WAIT2 = 5,
        BPF_TCP_TIME_WAIT = 6,
        BPF_TCP_CLOSE = 7,
        BPF_TCP_CLOSE_WAIT = 8,
        BPF_TCP_LAST_ACK = 9,
        BPF_TCP_LISTEN = 10,
        BPF_TCP_CLOSING = 11,
        BPF_TCP_NEW_SYN_RECV = 12,
        BPF_TCP_MAX_STATES = 13,
};

struct bpf_sock_ops {
        __u32 op;
        union {
                __u32 args[4];
                __u32 reply;
                __u32 replylong[4];
        };
        __u32 family;
        __u32 remote_ip4;
        __u32 local_ip4;
        __u32 remote_ip6[4];
        __u32 local_ip6[4];
        __u32 remote_port;
        __u32 local_port;
        __u32 is_fullsock;
        __u32 snd_cwnd;
        __u32 srtt_us;
        __u32 bpf_sock_ops_cb_flags;
        __u32 state;
        __u32 rtt_min;
        __u32 snd_ssthresh;
        __u32 rcv_nxt;
        __u32 snd_nxt;
        __u32 snd_una;
        __u32 mss_cache;
        __u32 ecn_flags;
        __u32 rate_delivered;
        __u32 rate_interval_us;
        __u32 packets_out;
        __u32 retrans_out;
        __u32 total_retrans;
        __u32 segs_in;
        __u32 data_segs_in;
        __u32 segs_out;
        __u32 data_segs_out;
        __u32 lost_out;
        __u32 sacked_out;
        __u32 sk_txhash;
        __u64 bytes_received;
        __u64 bytes_acked;
        union {
                struct bpf_sock *sk;
        };
        union {
                void *skb_data;
        };
        union {
                void *skb_data_end;
        };
        __u32 skb_len;
        __u32 skb_tcp_flags;
};

struct sk_msg_md {
        union {
                void *data;
        };
        union {
                void *data_end;
        };
        __u32 family;
        __u32 remote_ip4;
        __u32 local_ip4;
        __u32 remote_ip6[4];
        __u32 local_ip6[4];
        __u32 remote_port;
        __u32 local_port;
        __u32 size;
        union {
                struct bpf_sock *sk;
        };
};

#endif
