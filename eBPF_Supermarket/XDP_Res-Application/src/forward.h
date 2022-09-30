#define IPV6_FLOWINFO_MASK              cpu_to_be32(0x0FFFFFFF)

struct route_item {
	int ifindex; 
	char eth_src[ETH_ALEN]; 
	char eth_dest[ETH_ALEN];
};

BPF_HASH(route_cache_v4,int,struct route_item);
BPF_HASH(route_cache_v6,struct in6_addr,struct route_item);

static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = (__force u32)iph->check;

	check += (__force u32)htons(0x0100);
	iph->check = (__force __sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline int record_to_cache_v4(int ip_daddr,struct bpf_fib_lookup *fib_params){
    struct route_item item;
	memset(&item, 0, sizeof(item));
	memcpy(&item.eth_dest, fib_params->dmac, ETH_ALEN);
	memcpy(&item.eth_src, fib_params->smac, ETH_ALEN);
	item.ifindex = fib_params->ifindex;
    return route_cache_v4.update(&ip_daddr, &item);
}


static __always_inline int record_to_cache_v6(struct in6_addr  *p_ipv6_daddr,struct bpf_fib_lookup *fib_params){
	struct route_item item;
	struct in6_addr ipv6_daddr;
	memset(&item, 0, sizeof(item));
	memcpy(&item.eth_dest, fib_params->dmac, ETH_ALEN);
	memcpy(&item.eth_src, fib_params->smac, ETH_ALEN);
	item.ifindex = fib_params->ifindex;
	memcpy(&ipv6_daddr, p_ipv6_daddr, sizeof(struct in6_addr));
	return route_cache_v6.update(&ipv6_daddr, &item);
}


static __always_inline int match_cache_v4(int ip_daddr,struct ethhdr *eth){
    struct route_item *pitem = NULL;
    pitem = route_cache_v4.lookup(&ip_daddr);
    if(pitem){
		memcpy(eth->h_dest, pitem->eth_dest, ETH_ALEN);
		memcpy(eth->h_source, pitem->eth_src, ETH_ALEN);
        return pitem->ifindex;
    }
    return -1;
}


static __always_inline int match_cache_v6(struct in6_addr  *p_ipv6_daddr,struct ethhdr *eth){
	struct route_item *pitem = NULL;
    pitem = route_cache_v6.lookup(p_ipv6_daddr);
	 if(pitem){
		memcpy(eth->h_dest, pitem->eth_dest, ETH_ALEN);
		memcpy(eth->h_source, pitem->eth_src, ETH_ALEN);
        return pitem->ifindex;
    }
    return -1;
}