#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define IPV6_FLOWINFO_MASK              cpu_to_be32(0x0FFFFFFF)

struct route_v4 {
	int ifindex; 
	char eth_src[ETH_ALEN]; 
	char eth_dest[ETH_ALEN];
};

BPF_HASH(route_cache_v4,int,struct route_v4);

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = (__force u32)iph->check;

	check += (__force u32)htons(0x0100);
	iph->check = (__force __sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline int record_to_cache_v4(int ip_daddr,struct bpf_fib_lookup *fib_params){
    struct route_v4 item;
	memset(&item, 0, sizeof(item));
	memcpy(&item.eth_dest, fib_params->dmac, ETH_ALEN);
	memcpy(&item.eth_src, fib_params->smac, ETH_ALEN);
	item.ifindex = fib_params->ifindex;
    return route_cache_v4.update(&ip_daddr, &item);
}

static __always_inline int match_cache_v4(int ip_daddr,struct ethhdr *eth){
    struct route_v4 *pitem = NULL;
    pitem = route_cache_v4.lookup(&ip_daddr);
    if(pitem){
		memcpy(eth->h_dest, pitem->eth_dest, ETH_ALEN);
		memcpy(eth->h_source, pitem->eth_src, ETH_ALEN);
        return pitem->ifindex;
    }
    return -1;
}

int xdp_fwd(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	u16 h_proto;
	u64 nh_off;
	int rc;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	h_proto = eth->h_proto;
	if (h_proto == htons(ETH_P_IP)) {
		iph = data + nh_off;

		if ((void *)iph + sizeof(struct iphdr) > data_end)
			return XDP_DROP;
        
		if (iph->ttl <= 1)
			return XDP_PASS;

        int match_if = match_cache_v4(iph->daddr,eth);
        if(match_if >0){
            ip_decrease_ttl(iph);
            return bpf_redirect(match_if,0);
        }
        
		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (h_proto == htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip6h = data + nh_off;
		if ((void *)ip6h + sizeof(struct ipv6hdr) > data_end)
			return XDP_DROP;

		if (ip6h->hop_limit <= 1)
			return XDP_PASS;

		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
	} else {
		return XDP_PASS;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		if (h_proto == htons(ETH_P_IP)){
		    ip_decrease_ttl(iph);
            record_to_cache_v4(iph->daddr,&fib_params);
            bpf_trace_printk("src:%d,dst:%d",ctx->ingress_ifindex,fib_params.ifindex);
        }
		else if (h_proto == htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		return bpf_redirect(fib_params.ifindex, 0);
	}

	return XDP_PASS;
}