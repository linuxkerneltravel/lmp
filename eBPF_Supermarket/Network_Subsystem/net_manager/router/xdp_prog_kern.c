// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: zxh8411728@163.com
//
// Kernel space BPF program 


#include <string.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h" 
#include "../common/parsing_helpers.h"


#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

//重定义
#undef AF_INET
#define AF_INET 2
#undef AF_INET6
#define AF_INET6 10
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

// 转发接口
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 256);
} tx_port SEC(".maps");

// 路由转发表缓存
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct rt_item);
	__uint(max_entries, MAX_RULES);
} rtcache_map4 SEC(".maps");


static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* Calculate packet length */
	__u64 bytes = data_end - data;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += bytes;

	return action;
}



/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}



static __always_inline
int mac_zero(const __u8 *mac_addr) {
    // 检查MAC地址是否不全为零
    for (int i = 0; i < ETH_ALEN; i++) {
        if (mac_addr[i] != 0)
            return 1; // 如果有一个字节不为零，返回1表示不为零
    }
    return 0; // 如果所有字节都为零，返回0表示全为零
}


static __always_inline
int ipv4_match(__u32 conn_addr, __u32 rule_addr) {
    // 直接比较IPv4地址和网络地址
	if( (!rule_addr) || (conn_addr == rule_addr) ) //0 , match all
		return 1;
	return 0;
}


static int match_rules_loop(__u32 index, void *ctx)
{
	struct rt_item *p_ctx = (struct rt_item *)ctx;


	struct rt_item *p_r = bpf_map_lookup_elem(&rtcache_map4, &index);
	if(!p_r){
		return 1; //out of range
	}
	

	if( ipv4_match(p_ctx->saddr, p_r->saddr) ) {
	
		memcpy(p_ctx->eth_source, p_r->eth_source, ETH_ALEN);
		memcpy(p_ctx->eth_dest, p_r->eth_dest, ETH_ALEN);
		

		/*
		bpf_printk("MAC: %02x:%02x:%02x:%02x:%02x:%02x", 
           p_ctx->eth_source[0], p_ctx->eth_source[1], p_ctx->eth_source[2],
           p_ctx->eth_source[3], p_ctx->eth_source[4], p_ctx->eth_source[5]);
		
		bpf_printk("MAC: %02x:%02x:%02x:%02x:%02x:%02x", 
           p_ctx->eth_dest[0], p_ctx->eth_dest[1], p_ctx->eth_dest[2],
           p_ctx->eth_dest[3], p_ctx->eth_dest[4], p_ctx->eth_dest[5]);
		
		
		bpf_printk("Port: %u", p_ctx->ifindex);
		*/
		

		return 1;
	}


	return 1;
}



static __always_inline 
int match_rules(struct rt_item *conn)
{
	struct rt_item *ctx = conn;
	
	bpf_loop(MAX_RULES, match_rules_loop, ctx, 0);

	
	/*
	bpf_printk("MAC: %02x:%02x:%02x:%02x:%02x:%02x", 
           coon_r.eth_source[0], coon_r.eth_source[1], coon_r.eth_source[2],
           coon_r.eth_source[3], coon_r.eth_source[4], coon_r.eth_source[5]);

	bpf_printk("MAC: %02x:%02x:%02x:%02x:%02x:%02x", 
           coon_r.eth_dest[0], coon_r.eth_dest[1], coon_r.eth_dest[2],
           coon_r.eth_dest[3], coon_r.eth_dest[4], coon_r.eth_dest[5]);

	bpf_printk("Port: %u", coon_r.ifindex);
	*/
	
	
	return 1;
}


/* Solution to packet03/assignment-4 */
SEC("xdp_rtcache")
int xdp_rtcache_prog(struct xdp_md *ctx)
{
	xdp_act action = XDP_PASS; 
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup ifib = {};
	struct hdr_cursor nh;
	int nh_type; //next header type
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	unsigned int ip4_saddr = 0;
	//unsigned ifindex = 2;
	int rc;
	struct rt_item nitem = {.saddr = 0, .eth_source = {0}, .eth_dest = {0}};


	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if(nh_type < 0)
		goto out;

	if (nh_type == bpf_htons(ETH_P_IP)) { 
		nh_type = parse_iphdr(&nh, data_end, &iph);

		if(nh_type < 0)
			goto out;
		
		
		if (iph->ttl <= 1)
			goto out;
		

		ip4_saddr = iph->saddr;

		nitem.saddr = ip4_saddr;
		
		// 首先精确查找转发表，如果找到就直接转发，不必再经历最长前缀匹配的慢速通配查找
		match_rules(&nitem);
	
		

		if (mac_zero(nitem.eth_dest)) {
			ip_decrease_ttl(iph);
			memcpy(eth->h_dest, nitem.eth_dest, ETH_ALEN);
			memcpy(eth->h_source, nitem.eth_source, ETH_ALEN);
			action = bpf_redirect_map(&tx_port, 0, 0);

			goto out;
		}

		// 否则执行最长前缀匹配了
		ifib.family = AF_INET;
		ifib.tos = iph->tos;
		ifib.l4_protocol = iph->protocol;
		ifib.sport	= 0;
		ifib.dport	= 0;
		ifib.tot_len	= bpf_ntohs(iph->tot_len);
		ifib.ipv4_src = iph->saddr;
		ifib.ipv4_dst = iph->daddr;
		ifib.ifindex = ctx->ingress_ifindex;
		

		rc = bpf_fib_lookup(ctx, &ifib, sizeof(ifib), 0);
		switch (rc) {
		case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
			ip_decrease_ttl(iph);
	
			memcpy(eth->h_dest, ifib.dmac, ETH_ALEN);
			memcpy(eth->h_source, ifib.smac, ETH_ALEN);
			action = bpf_redirect(ifib.ifindex, 0);
			goto out;
			break;
		case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
		case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
		case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
			action = XDP_DROP;
			goto out;
			break;
		case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
		case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
		case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
			/* PASS */
			goto out;
			break;
		}

	} else if (nh_type == bpf_htons(ETH_P_IPV6)) {
		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);

		struct in6_addr *src = (struct in6_addr *) ifib.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) ifib.ipv6_dst;

		if(nh_type < 0)
			goto out;

		if (ip6h->hop_limit <= 1)
			goto out;

		ifib.family	= AF_INET6;
		ifib.flowinfo	= *(__be32 *) ip6h & IPV6_FLOWINFO_MASK;
		ifib.l4_protocol	= ip6h->nexthdr;
		ifib.sport	= 0;
		ifib.dport	= 0;
		ifib.tot_len = bpf_ntohs(ip6h->payload_len);
		*src = ip6h->saddr;
		*dst = ip6h->daddr;
		ifib.ifindex = ctx->ingress_ifindex;

		rc = bpf_fib_lookup(ctx, &ifib, sizeof(ifib), 0);
		switch (rc) {
		case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
			ip6h->hop_limit--;

			memcpy(eth->h_dest, ifib.dmac, ETH_ALEN);
			memcpy(eth->h_source, ifib.smac, ETH_ALEN);
			action = bpf_redirect(ifib.ifindex, 0);
			goto out;
			break;
		case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
		case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
		case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
			action = XDP_DROP;
			break;
		case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
		case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
		case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
		case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
		case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
			/* PASS */
			break;
		}

	}
	else {
		goto out;
	}

	
	
out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
