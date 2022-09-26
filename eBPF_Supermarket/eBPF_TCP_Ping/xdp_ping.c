#include <linux/byteorder/little_endian.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/ctx/xdp.h>
#include <bpf/builtins.h>
#include <bpf/helpers.h>
#include <lib/endian.h>
#include <lib/csum.h>

#define PING_PORT           65532

#define ETH_HLEN            __ETH_HLEN

#define IP_HLEN             sizeof(struct iphdr)
#define TCP_CSUM_OFFSET     (ETH_HLEN + IP_HLEN + offsetof(struct tcphdr, check))
#define ACK_SEQ_OFFSET      (ETH_HLEN + IP_HLEN + offsetof(struct tcphdr, ack_seq))

#define TCP_FLAG_FIELD_OFFSET ( (__u64)&tcp_flag_word( (struct tcphdr *)0 ) )
#define TCP_FLAG_OFFSET       (ETH_HLEN + IP_HLEN + TCP_FLAG_FIELD_OFFSET)

#define bpf_printk(fmt, ...)    ({                             \
    const char ____fmt[] = fmt;                                \
    trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);     \
})

struct vlanhdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static inline void swap_mac(struct ethhdr *eth)
{
    __u8 tmp_mac[ETH_ALEN];

    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);
}

static inline void swap_ip(struct iphdr *ip)
{
    struct in_addr tmp_ip;

    memcpy(&tmp_ip, &ip->saddr, sizeof(tmp_ip));
    memcpy(&ip->saddr, &ip->daddr, sizeof(tmp_ip));
    memcpy(&ip->daddr, &tmp_ip, sizeof(tmp_ip));
}

static inline void swap_port(struct tcphdr *tcp)
{
    __u16 tmp_port;

    memcpy(&tmp_port, &tcp->source, sizeof(tmp_port));
    memcpy(&tcp->source, &tcp->dest, sizeof(tmp_port));
    memcpy(&tcp->dest, &tmp_port, sizeof(tmp_port));
}

__section("xdp-ping")
int xdp_ping(struct xdp_md *ctx)
{
    int ret = 0;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* eth */
    struct ethhdr *eth = data;
    __u64 nh_off = sizeof(*eth);
    if (unlikely(data + nh_off > data_end))
        return XDP_DROP;

    __be16 h_proto = eth->h_proto;

    /* vlan */
    __u64 vlanhdr_len = 0;
    // handle double tags in ethernet frames
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (bpf_htons(ETH_P_8021Q) == h_proto || bpf_htons(ETH_P_8021AD) == h_proto) {
            struct vlanhdr *vhdr = data + nh_off;

            nh_off += sizeof(*vhdr);
            if (data + nh_off > data_end)
                return XDP_DROP;

            vlanhdr_len += sizeof(*vhdr);
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    /* ipv4 */
    if (bpf_htons(ETH_P_IP) != h_proto)
        return XDP_PASS;

    struct iphdr *ip = data + nh_off;
    if (unlikely((void *)ip + sizeof(*ip) > data_end))
        return XDP_DROP;

    /* tcp */
    if (IPPROTO_TCP != ip->protocol)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if (unlikely((void *)tcp + sizeof(*tcp) > data_end))
        return XDP_DROP;

    if (PING_PORT != bpf_ntohs(tcp->dest) || 1 != tcp->syn)
        return XDP_PASS;

    /* main logic */

    swap_mac(eth);
    swap_ip(ip);
    swap_port(tcp);

    __u16 *tcp_flag = (void *)tcp + TCP_FLAG_FIELD_OFFSET;
    __u16 old_tcp_flag = *tcp_flag;
    __u16 new_tcp_flag = *tcp_flag;

    /* clear syn bit */
    new_tcp_flag &= ~TCP_FLAG_SYN;
    /* set rst bit */
    new_tcp_flag |= TCP_FLAG_RST;
    /* set ack bit */
    new_tcp_flag |= TCP_FLAG_ACK;

    ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_tcp_flag, new_tcp_flag, 0);
    if (unlikely(ret)) {
        bpf_printk("l4_csum_replace tcp_flag error\n");
        return XDP_DROP;
    }

    memcpy(data + TCP_FLAG_OFFSET + vlanhdr_len, &new_tcp_flag, sizeof(new_tcp_flag));

    /* calculate and set ack sequence */
    __be32 old_ack_seq = tcp->ack_seq;
    __be32 new_ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);

    ret = l4_csum_replace(ctx, TCP_CSUM_OFFSET + vlanhdr_len, old_ack_seq, new_ack_seq, 0);
    if (unlikely(ret)) {
        bpf_printk("l4_csum_replace ack_seq error\n");
        return XDP_DROP;
    }

    memcpy(data + ACK_SEQ_OFFSET + vlanhdr_len, &new_ack_seq, sizeof(new_ack_seq));

    return XDP_TX;
}

BPF_LICENSE("GPL");
