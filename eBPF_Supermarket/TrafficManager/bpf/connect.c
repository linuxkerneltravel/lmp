// +build ignore

#include "connect.h"

const __be32 service_ip = 0x846F070A;   // 10.7.111.132
const __be32 pod_ip     = 0x0100007F;   // 127.0.0.1
const __be16 service_port = 0x5000;     // 80   (0x0  * 256 + 0x50)
const __be16 pod_port     = 0x901f;     // 8080 (0x1f * 256 + 0x144)

static int sock4_forward_entry(struct bpf_sock_addr *ctx)
{
    __be32 ori_dst_ip   = ctx_get_dst_ip(ctx);
    __be16 ori_dst_port = ctx_get_dst_port(ctx);

    bpf_printk("original:   %08x:%04x", ori_dst_ip, ori_dst_port);
    bpf_printk("service:    %08x:%04x", service_ip, service_port);
    bpf_printk("pod:        %08x:%04x", pod_ip, pod_port);

    if(ori_dst_ip == service_ip && ori_dst_port == service_port)
    {
        bpf_printk("redirect to %08x:%04x", pod_ip, pod_port);
        ctx_set_ip(ctx, pod_ip);
        ctx_set_port(ctx, pod_port);
    }
    else
    {
        bpf_printk("skipped, not modified");
    }
    return 0;
}

SEC("cgroup/connect4")
int sock4_connect(struct bpf_sock_addr *ctx)
{
    sock4_forward_entry(ctx);
    return SYS_PROCEED;
}

char _license[] SEC("license") = "GPL";
