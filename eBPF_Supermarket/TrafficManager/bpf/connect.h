#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SYS_PROCEED 1

// sudo cat  /sys/kernel/debug/tracing/trace_pipe

#define print_ip_formatted(ip)                          \
({                                                      \
    bpf_printk("ip1: %d.%d",                            \
                ip%256, (ip/256)%256);                  \
    bpf_printk("ip2: %d.%d\n",                          \
                (ip/65536)%256, (ip/16711680)%256);     \
})

static __always_inline __be32 ctx_get_dst_ip(const struct bpf_sock_addr *ctx)
{
    volatile __u32 dst_ip = ctx->user_ip4;
    return (__be32)dst_ip;
}

static __always_inline __be16 ctx_get_dst_port(const struct bpf_sock_addr *ctx)
{
	volatile __u32 dport = ctx->user_port;
	return (__be16)dport;
}

static __always_inline void ctx_set_ip(struct bpf_sock_addr *ctx, __be32 dst_ip)
{
	ctx->user_ip4 = (__u32)dst_ip;
}

static __always_inline void ctx_set_port(struct bpf_sock_addr *ctx, __be16 dport)
{
	ctx->user_port = (__u32)dport;
}
