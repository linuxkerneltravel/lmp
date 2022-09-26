#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "config.h"
#include "map.h"
#include "filter.h"
#include "forward.h"

#ifdef COUNT
static __always_inline void count_inc(int key){
    count.increment(key);
}
#endif

static __always_inline int handle_ipv4(struct xdp_md *xdp,int *err_code)
{
    void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
    struct ethhdr *eth = data;
    struct iphdr *iph = data + sizeof(struct ethhdr);
    int act = XDP_PASS;

    if ((void *)iph + sizeof(struct iphdr) > data_end)
		return XDP_DROP;
    
    if (iph->ttl <= 1){
		return XDP_PASS;
	}
    
    //filter
    struct metainfo info;

    act = get_port(iph + sizeof(struct iphdr), data_end, iph->protocol, &info.sport ,&info.dport);
    if(act == XDP_DROP)
        return XDP_DROP;
    
    info.saddr = iph->saddr;
    info.daddr = iph->daddr;
    info.ipproto = iph->protocol;
    
    act = match_rule(&info);
    if(act == XDP_DROP)
        return XDP_DROP;
    
    //forward

    int match_if = match_cache_v4(iph->daddr,eth); //fast path
    if(match_if >0){
        ip_decrease_ttl(iph);
        return XDP_REDIRECT;
    }

    struct bpf_fib_lookup fib_params; //slow path
    memset(&fib_params, 0, sizeof(fib_params));
    fib_params.family	= AF_INET;
	fib_params.tos		= iph->tos;
	fib_params.l4_protocol	= iph->protocol;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.tot_len	= ntohs(iph->tot_len);
	fib_params.ipv4_src	= iph->saddr;
	fib_params.ipv4_dst	= iph->daddr;
    fib_params.ifindex = xdp->ingress_ifindex;

    int rc = bpf_fib_lookup(xdp, &fib_params, sizeof(fib_params), 0);
    if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
        ip_decrease_ttl(iph);
        record_to_cache_v4(iph->daddr,&fib_params);
        memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        bpf_redirect(fib_params.ifindex,0);
        return XDP_REDIRECT;
    }
    else
        *err_code = rc;

    return XDP_PASS;
}

static __always_inline int handle_ipv6(struct xdp_md *xdp,int *err_code)
{
    void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);

    if ((void *)ip6h + sizeof(struct ipv6hdr) > data_end)
		return XDP_DROP;

    if (ip6h->hop_limit <= 1){
        return XDP_PASS;    
	}

    //forward
    int match_if = match_cache_v6(&ip6h->daddr,eth);//fast path
    if(match_if >0){
        ip6h->hop_limit--; 
        return XDP_REDIRECT;
    }

    struct bpf_fib_lookup fib_params; //slow path
    memset(&fib_params, 0, sizeof(fib_params));
    struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;//slow path
	struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;
    fib_params.family	= AF_INET6;
	fib_params.flowinfo	= *(__be32 *)ip6h & IPV6_FLOWINFO_MASK;
	fib_params.l4_protocol	= ip6h->nexthdr;
	fib_params.sport	= 0;
	fib_params.dport	= 0;
	fib_params.tot_len	= ntohs(ip6h->payload_len);
    fib_params.ifindex = xdp->ingress_ifindex;
    *src			= ip6h->saddr;
	*dst			= ip6h->daddr;

    int rc = bpf_fib_lookup(xdp, &fib_params, sizeof(fib_params), 0);
    if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
        ip6h->hop_limit--; 
		record_to_cache_v6(&ip6h->daddr,&fib_params);
        memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        bpf_redirect(fib_params.ifindex,0);
        return XDP_REDIRECT;
    }
    else
        *err_code = rc;

    return XDP_PASS;
}

int xdp_prog(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth = data;
	__u16 h_proto;
    int act = XDP_PASS;
    int err_code = 0;

	if ((void *)eth + sizeof(struct ethhdr) > data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;

    
	if (h_proto == htons(ETH_P_IP))
		act = handle_ipv4(xdp,&err_code);
	else if (h_proto == htons(ETH_P_IPV6))
		act = handle_ipv6(xdp,&err_code);
    
    switch(act)
    {
        case XDP_REDIRECT:
            goto redirect;
            break;
        case XDP_DROP:
            goto drop;
            break;
        dafault:
            goto pass;
            break;
    }
    pass:
        #ifdef COUNT
        count_inc(XDP_PASS);
        #endif
        return XDP_PASS;
    redirect:
        #ifdef COUNT
        count_inc(XDP_REDIRECT);
        #endif
        return XDP_REDIRECT;
    drop:
        #ifdef COUNT
        count_inc(XDP_DROP);
        #endif
        return XDP_DROP;
}
