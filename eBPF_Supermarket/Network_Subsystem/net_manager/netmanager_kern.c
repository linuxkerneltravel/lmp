/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h" 
#include "./common/parsing_helpers.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

//重定义
#undef AF_INET
#define AF_INET 2
#undef AF_INET6
#define AF_INET6 10
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

// config map
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, __u16);
	__uint(max_entries, 1);
} print_info_map SEC(".maps");

// 数据包统计
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

// ipv4—filter
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct rules_ipv4);
	__uint(max_entries, MAX_RULES);
} rules_ipv4_map SEC(".maps");

// mac—filter
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct rules_mac);
	__uint(max_entries, MAX_RULES);
} rules_mac_map SEC(".maps");

// router
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

// 会话保持
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct conn_ipv4_key);
	__type(value, struct conn_ipv4_val);
	__uint(max_entries, MAX_RULES);
} conn_ipv4_map SEC(".maps");

struct sock_key {
	__u32 sip4;    // 源 IP
	__u32 dip4;    // 目的 IP
	__u8  family;  // 协议类型
	__u8  pad1;    // this padding required for 64bit alignment
	__u16 pad2;    // else ebpf kernel verifier rejects loading of the program
	__u32 pad3;
	__u32 sport;   // 源端口
	__u32 dport;   // 目的端口
} __attribute__((packed));

struct{
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key,struct sock_key);
	__type(value, int);
	__uint(max_entries, 65535);
}sock_ops_map SEC(".maps");

#define FORCE_READ(x) (*(volatile typeof(x) *)&(x))

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

/*路由功能*/

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
		

		return 1;
	}


	return 1;
}

static __always_inline 
int match_rules(struct rt_item *conn)
{
	struct rt_item *ctx = conn;
	
	bpf_loop(MAX_RULES, match_rules_loop, ctx, 0);
	
	return 1;
}

/*使用 IP 进行过滤*/

struct match_rules_loop_ctx{
	__u16 action;
	__u16 next_rule;
	struct conn_ipv4 *conn;
};

static __always_inline
int ipv4_cidr_match(__u32 ip_addr, __u32 network_addr, __u8 cidr) {
	if(network_addr == 0 && cidr == 0)
        return 1;
	
    __u32 subnet_mask = (0xFFFFFFFFU << (32 - cidr)) & 0xFFFFFFFFU;

    __u32 masked_ip = ip_addr & subnet_mask;
    __u32 masked_network = network_addr & subnet_mask;
    return masked_ip == masked_network;
}

static __always_inline
int port_match(__u16 conn_port, __u16 rule_port){
	if( (!rule_port) || (rule_port == conn_port) ) //0 , match all
		return 1;
	return 0;
}

static int match_rules_ipv4_loop(__u32 index, void *ctx)
{
	int i = 0;
	unsigned char *saddr;
	unsigned char *daddr;
	struct match_rules_loop_ctx *p_ctx = (struct match_rules_loop_ctx *)ctx;
	if(index != p_ctx->next_rule)
		return 0;

	struct rules_ipv4 *p_r = bpf_map_lookup_elem(&rules_ipv4_map, &index);
	if(!p_r){
		return 1; //out of range
	}

	p_ctx->next_rule = p_r->next_rule;

	if(index == 0)
		goto out_match_rules_ipv4_loop;
	bpf_printk("match_rules_ipv4_loop %d",index);
	if( ipv4_cidr_match(p_ctx->conn->saddr, p_r->saddr, p_r->saddr_mask) && 
		ipv4_cidr_match(p_ctx->conn->daddr, p_r->daddr, p_r->daddr_mask) &&
		port_match(p_ctx->conn->sport, p_r->sport) &&
		port_match(p_ctx->conn->dport, p_r->dport) &&
		port_match(p_ctx->conn->ip_proto, p_r->ip_proto) ) 
	{
		p_ctx->action = p_r->action;
		__u8 *print_info=(__u8*)bpf_map_lookup_elem(&print_info_map,&i);
		if(!print_info) return 1;
		if(print_info){
			saddr = (unsigned char *)&p_ctx->conn->saddr;
			daddr = (unsigned char *)&p_ctx->conn->daddr;
			//bpf_printk("%s ,%s",saddr,daddr);
			bpf_printk("src: %lu.%lu.%lu.%lu:%d" ,(unsigned long)saddr[3], (unsigned long)saddr[2], (unsigned long)saddr[1], (unsigned long)saddr[0],p_ctx->conn->sport);
			bpf_printk("dst: %lu.%lu.%lu.%lu:%d" ,(unsigned long)daddr[3], (unsigned long)daddr[2], (unsigned long)daddr[1], (unsigned long)daddr[0],p_ctx->conn->dport);
			bpf_printk("prot:%d ,action:%d ,index:%d" ,p_ctx->conn->ip_proto,p_ctx->action, index);
			bpf_printk("-----------------------------------");
		}

		return 1;
	}

out_match_rules_ipv4_loop:
	if(p_r->next_rule == 0)
		return 1; //go out loop

	return 0;
}

static __always_inline
xdp_act match_rules_ipv4(struct conn_ipv4 *conn)
{
	struct match_rules_loop_ctx ctx = {.action = XDP_PASS, .conn = conn, .next_rule = 0};
	
	
	for(int i=0; i<MAX_RULES; i++){
		if(match_rules_ipv4_loop(i,&ctx))
			break;
	}

	return ctx.action;
}

SEC("xdp")
int xdp_entry_ipv4(struct xdp_md *ctx)
{
	xdp_act action = XDP_PASS; 
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	int nh_type; //next header type
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph; 
	struct udphdr *udph;
	struct conn_ipv4 conn = {.saddr = 0, .daddr = 0, .sport = 0, .dport = 0, .ip_proto = 0};

	//bpf_printk("xdp_entry_ipv4");
	nh.pos = data;
	
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if(nh_type < 0)
		goto out;

	if (nh_type == bpf_htons(ETH_P_IP)) { 

		nh_type = parse_iphdr(&nh, data_end, &iph);

		if(nh_type < 0)
			goto out;
		
		if (nh_type == IPPROTO_TCP) {
			if(parse_tcphdr(&nh, data_end, &tcph) < 0)
				goto out;
			
			conn.sport = bpf_ntohs(tcph -> source);
			conn.dport = bpf_ntohs(tcph -> dest);
			
		}
		else if(nh_type == IPPROTO_UDP){
			if(parse_udphdr(&nh, data_end, &udph) < 0){
				goto out;
			}
			conn.sport = bpf_ntohs(udph -> source);
			conn.dport = bpf_ntohs(udph -> dest);
		}
		else if(nh_type == IPPROTO_ICMP){
			conn.sport = 0;
			conn.dport = 0;
		}
		conn.saddr = bpf_ntohl(iph -> saddr);
		conn.daddr = bpf_ntohl(iph -> daddr);
		conn.ip_proto = nh_type;

		// #ifdef DEBUG_PRINT_EVERY
		// if(conn.dport != 22)
		// 	bpf_printk("conn(%u:%u to %u:%u)", conn.saddr, conn.sport, conn.daddr, conn.dport);
		// #endif

		action = match_rules_ipv4(&conn);

	}
	
		
out:
	return xdp_stats_record_action(ctx, action);
}




/* Solution to packet03/assignment-4 */
SEC("xdp")
int xdp_entry_router1(struct xdp_md *ctx)
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
		match_rules(&nitem);//rtcache_map4
	
		

		if (mac_zero(nitem.eth_dest)) {
			ip_decrease_ttl(iph);
			memcpy(eth->h_dest, nitem.eth_dest, ETH_ALEN);
			memcpy(eth->h_source, nitem.eth_source, ETH_ALEN);
			action = bpf_redirect_map(&tx_port, 0, 0);//这里可能需要改

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

struct match_rules_loop_mac_ctx{
	__u16 action;
	__u16 next_rule;
	struct conn_mac *conn;
};

static inline int bpf_memcmp(const void *a, const void *b, size_t len) {
    const unsigned char *p1 = a;
    const unsigned char *p2 = b;
    size_t i;

    for (i = 0; i < len; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}
static __always_inline
int mac_match(__u8 *conn_mac, __u8 *rule_mac) {
    __u8 zero_mac[ETH_ALEN] = {0};  // 全零的MAC地址

    // 如果rule_mac全为零，匹配所有MAC地址
    if (bpf_memcmp(rule_mac, zero_mac, ETH_ALEN) == 0) {
        return 1;
    }

    // 如果rule_mac的后三个字节为零，且前三个字节与conn_mac相同
    if (bpf_memcmp(&rule_mac[3], zero_mac, 3) == 0) {
        if (bpf_memcmp(conn_mac, rule_mac, 3) == 0) {
            return 1;  // 匹配前三字节
        }
    }

    // 检查规则MAC与连接MAC是否完全匹配
    if (bpf_memcmp(rule_mac, conn_mac, ETH_ALEN) == 0) {
        return 1;  // 完全匹配
    }

    return 0;  // 不匹配
}


static int match_rules_mac_loop(__u32 index, void *ctx)
{
	struct match_rules_loop_mac_ctx *p_ctx = (struct match_rules_loop_mac_ctx *)ctx;
	if(index != p_ctx->next_rule)
		return 0;
	struct rules_mac *p_r = bpf_map_lookup_elem(&rules_mac_map, &index);
	if(!p_r){
		return 1; //out of range
	}
	p_ctx->next_rule = p_r->next_rule;
	
	if(index == 0)
		goto out_match_rules_mac_loop;
	//bpf_printk("match_rules_ipv4_loop %d",index);
	// bpf_printk("MAC_SRC: %02x:%02x:%02x:%02x:%02x:%02x\n",p_r->source[0], p_r->source[1], p_r->source[2],p_r->source[3], p_r->source[4], p_r->source[5]);
	// bpf_printk("MAC_DEST: %02x:%02x:%02x:%02x:%02x:%02x ,Action: %d\n",p_r->dest[0], p_r->dest[1], p_r->dest[2],p_r->dest[3], p_r->dest[4], p_r->dest[5], 
	// 					  p_r->action);
	if(mac_match(p_ctx->conn->dest, p_r->dest)&&mac_match(p_ctx->conn->source, p_r->source)) 
	{
		p_ctx->action = p_r->action;
		return 1;
	}

out_match_rules_mac_loop:
	if(p_r->next_rule == 0)
		return 1; //go out loop

	return 0;
}

static __always_inline
xdp_act match_rules_mac(struct conn_mac *conn)
{
	struct match_rules_loop_mac_ctx ctx = {.action = XDP_PASS, .conn = conn, .next_rule = 0};
	
	
	for(int i=0; i<MAX_RULES; i++){
		if(match_rules_mac_loop(i,&ctx))
			break;
	}

	return ctx.action;
}

/* accept ethernet addresses and filter everything else */
SEC("xdp")
int xdp_entry_mac(struct xdp_md *ctx)
{
	xdp_act action = XDP_PASS; 
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	int nh_type; //next header type
	struct ethhdr *eth;
	struct conn_mac conn = {
    	.dest = {0},    // 初始化 dest 成员为全零
    	.source = {0}   // 初始化 source 成员为全零
	};
	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if(nh_type < 0)
		goto out;

	//action = match_rules_ipv4(&eth->h_source);

	// /* check if src mac is in src_macs map */
	// value = bpf_map_lookup_elem(&src_macs, eth->h_source);
	// if (value) {
    //     action = *value;
	// 	goto out;
    // }
	for (int i = 0; i < ETH_ALEN; i++) {
        conn.source[i] = eth->h_source[i];
        conn.dest[i] = eth->h_dest[i];
    }
	action = match_rules_mac(&conn);

out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp")
int xdp_entry_state(struct xdp_md *ctx)
{
	__u32 action = XDP_PASS; 
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	int nh_type; //next header type
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *tcph; 
	struct udphdr *udph;
	struct icmphdr *icmph;
	unsigned char *saddr;
	unsigned char *daddr;

	// 定义IPv4连接关键信息
	struct conn_ipv4_key conn_k = {.saddr = 0, .daddr = 0, .sport = 0, .dport = 0, .proto = 0};
	nh.pos = data;
	
	// 如果下一个头部类型为IPv4
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if(nh_type < 0)
		goto out;

	if (nh_type == bpf_htons(ETH_P_IP)) { 

		nh_type = parse_iphdr(&nh, data_end, &iph);

		if(nh_type < 0)
			goto out;
		
		conn_k.saddr = bpf_ntohl(iph -> saddr);
		conn_k.daddr = bpf_ntohl(iph -> daddr);

		conn_k.proto = nh_type;

		saddr = (unsigned char *)&conn_k.saddr;
		daddr = (unsigned char *)&conn_k.daddr;
		
		// 如果下一个头部类型为TCP
		if (nh_type == IPPROTO_TCP) {

			if(parse_tcphdr(&nh, data_end, &tcph) < 0)
				goto out;
			// 获取TCP连接信息
			conn_k.sport = bpf_ntohs(tcph -> source);
			conn_k.dport = bpf_ntohs(tcph -> dest);
			// bpf_printk("conn(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u)",
			// 		(unsigned long)saddr[0], (unsigned long)saddr[1], (unsigned long)saddr[2], (unsigned long)saddr[3],conn_k.sport,
			// 		(unsigned long)daddr[0], (unsigned long)daddr[1], (unsigned long)daddr[2], (unsigned long)daddr[3],conn_k.dport);
			// 查找IPv4连接映射表中的值
			// 如果找到，就说明该连接已经存在，可以在原有连接信息的基础上进行处理。
			// 如果没有找到，可能是首次遇到这个连接，可以进行一些初始化操作，例如创建新的连接信息并添加到哈希表中。
			struct conn_ipv4_val *p_conn_v = bpf_map_lookup_elem(&conn_ipv4_map, &conn_k);
			if(!p_conn_v){
				if(tcph->syn && tcph->ack){ //客户端
					struct conn_ipv4_val conn_v = {.tcp_state = TCP_S_ESTABLISHED,.rid=1};
					// 将新的连接项插入到 IPv4 连接映射中
					bpf_map_update_elem(&conn_ipv4_map, &conn_k, &conn_v, BPF_ANY);
					// 输出日志信息，表示创建了一个新的连接项
					bpf_printk("tcp(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u),state:%s,%s",
					(unsigned long)saddr[0], (unsigned long)saddr[1], (unsigned long)saddr[2], (unsigned long)saddr[3],conn_k.sport,
					(unsigned long)daddr[0], (unsigned long)daddr[1], (unsigned long)daddr[2], (unsigned long)daddr[3],conn_k.dport,
					"ESTABLISHED",conn_v.rid?"client":"service");
				}
				else if(tcph->syn){ //客户端
					struct conn_ipv4_val conn_v = {.tcp_state = TCP_S_SYN_RECV,.rid=0};
					// 将新的连接项插入到 IPv4 连接映射中
					bpf_map_update_elem(&conn_ipv4_map, &conn_k, &conn_v, BPF_ANY);
					// 输出日志信息，表示创建了一个新的连接项
					bpf_printk("tcp(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u),state:%s,%s",
					(unsigned long)saddr[0], (unsigned long)saddr[1], (unsigned long)saddr[2], (unsigned long)saddr[3],conn_k.sport,
					(unsigned long)daddr[0], (unsigned long)daddr[1], (unsigned long)daddr[2], (unsigned long)daddr[3],conn_k.dport,
					"SYN-RECV",conn_v.rid?"client":"service");
				}
				goto out;
			}
			// 如果查找成功，继续处理连接项
			// 如果TCP报文的标志位包含RST（复位），则删除连接项并输出相应的日志信息
			if(tcph->rst){
				bpf_map_delete_elem(&conn_ipv4_map, &conn_k);
				bpf_printk("tcp(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u),state:%s,%s",
					(unsigned long)saddr[0], (unsigned long)saddr[1], (unsigned long)saddr[2], (unsigned long)saddr[3],conn_k.sport,
					(unsigned long)daddr[0], (unsigned long)daddr[1], (unsigned long)daddr[2], (unsigned long)daddr[3],conn_k.dport,
					"RST",p_conn_v->rid?"client":"service");
				goto out;
			}
			if(p_conn_v->rid) //客户端
			{
				// 如果连接项的TCP状态为ESTABLISHED并且收到了ack，将TCP状态更新为FIN_WAIT2
				if(p_conn_v->tcp_state == TCP_S_ESTABLISHED && tcph->ack){
					p_conn_v->tcp_state = TCP_S_FIN_WAIT2;
					goto out_tcp_conn;
				}
			}
			if(!p_conn_v->rid)//服务端
			{
				// 如果连接项的TCP状态为SYN_RECV并且收到了ACK，将TCP状态更新为ESTABLISHED
				if(p_conn_v->tcp_state == TCP_S_SYN_RECV && tcph->ack){
					p_conn_v->tcp_state = TCP_S_ESTABLISHED;
					goto out_tcp_conn;
				}
				// 如果连接项的TCP状态为ESTABLISHED并且收到了FIN，将TCP状态更新为FIN_WAIT1
				if(p_conn_v->tcp_state == TCP_S_ESTABLISHED && tcph->fin){
					p_conn_v->tcp_state = TCP_S_CLOSE_WAIT;
					goto out_tcp_conn;
				}
				// 如果连接项的TCP状态为CLOSE_WAIT且收到了FIN和ACK，将TCP状态更新为FIN_WAIT2
				if(p_conn_v->tcp_state == TCP_S_CLOSE_WAIT && tcph->ack){
					p_conn_v->tcp_state = TCP_S_CLOSE;
					goto out_tcp_conn;
				}
			}
			const char *tcp_state_str;

			// 根据连接状态设置对应的字符串
			out_tcp_conn:
				if(p_conn_v->tcp_state == TCP_S_CLOSE||p_conn_v->tcp_state == TCP_S_FIN_WAIT2){
					// 如果是CLOSE状态，从映射表中删除连接信息
					bpf_map_delete_elem(&conn_ipv4_map, &conn_k);
				}else{
					// 否则更新映射表中的连接信息
					bpf_map_update_elem(&conn_ipv4_map, &conn_k, p_conn_v, BPF_EXIST);
				}
				// 根据连接状态打印日志
				switch(p_conn_v->tcp_state) {
					case TCP_S_SYN_SENT:
						tcp_state_str = "SYN_SENT";
						break;
					case TCP_S_SYN_RECV:
						tcp_state_str = "SYN_RECV";
						break;
					case TCP_S_ESTABLISHED:
						tcp_state_str = "ESTABLISHED";
						break;
					case TCP_S_FIN_WAIT1:
						tcp_state_str = "FIN_WAIT1";
						break;
					case TCP_S_FIN_WAIT2:
						tcp_state_str = "FIN_WAIT2";
						break;
					case TCP_S_CLOSE_WAIT:
						tcp_state_str = "CLOSE_WAIT";
						break;
					case TCP_S_CLOSE:
						tcp_state_str = "CLOSE";
						break;
					default:
						tcp_state_str = "";
				}
				bpf_printk("tcp(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u),state:%s,%s",
					(unsigned long)saddr[0], (unsigned long)saddr[1], (unsigned long)saddr[2], (unsigned long)saddr[3],conn_k.sport,
					(unsigned long)daddr[0], (unsigned long)daddr[1], (unsigned long)daddr[2], (unsigned long)daddr[3],conn_k.dport,
					tcp_state_str,p_conn_v->rid?"client":"service");			
				goto out;
		}
		else if(nh_type == IPPROTO_UDP){
			// 如果是UDP包，解析UDP头部并获取端口信息
			if(parse_udphdr(&nh, data_end, &udph) < 0){
				goto out;
			}
			conn_k.sport = bpf_ntohs(udph -> source);
			conn_k.dport = bpf_ntohs(udph -> dest);
			bpf_printk("udp(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u),len=%lu",
					(unsigned long)saddr[3], (unsigned long)saddr[2], (unsigned long)saddr[1], (unsigned long)saddr[0],conn_k.sport,
					(unsigned long)daddr[3], (unsigned long)daddr[2], (unsigned long)daddr[1], (unsigned long)daddr[0],conn_k.dport,
					__bpf_ntohs(udph -> len));			
		}
		else if(nh_type == IPPROTO_ICMP){
			// 如果是ICMP
			if(parse_icmphdr(&nh, data_end, &icmph) < 0){
				goto out;
			}
			bpf_printk("icmp(%lu.%lu.%lu.%lu->%lu.%lu.%lu.%lu),type=%u,code=%u",
					(unsigned long)saddr[3], (unsigned long)saddr[2], (unsigned long)saddr[1], (unsigned long)saddr[0],
					(unsigned long)daddr[3], (unsigned long)daddr[2], (unsigned long)daddr[1], (unsigned long)daddr[0],
					icmph->type,icmph->code);			
		}
		#ifdef DEBUG_PRINT_EVERY
		// 打印除SSH协议以外的所有连接信息
		if(conn.dport != 22)
			bpf_printk("icmp(%u:%u to %u:%u)", conn.saddr, conn.sport, conn.daddr, conn.dport);
		#endif

	}
	
		
out:
	return xdp_stats_record_action(ctx, action);
	
}

// 最简单的一个转发表项
struct rt_item_tab{
	int ifindex; // 转发出去的接口
	char eth_source[ETH_ALEN]; // 封装帧的源MAC地址。
	char eth_dest[ETH_ALEN]; // 封装帧的目标MAC地址。
};

// 路由转发表缓存
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct rt_item_tab);
	__uint(max_entries, MAX_RULES);
} rtcache_map SEC(".maps");
// 递减TTL还是要的
static __always_inline int __ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}
// 字节码的C程序本身
SEC("xdp")
int xdp_entry_router(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup ifib;
	struct ethhdr *eth = data;
	struct iphdr *iph;
	struct rt_item_tab *pitem = NULL;
	unsigned int daddr = 0;
	__u16 h_proto;
	__u64 nh_off;
	char fast_info[] = "Fast path to [%d]\n";
	char slow_info[] = "Slow path to [%d]\n";
	int action = XDP_DROP;
	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		return XDP_DROP;
	}

	__builtin_memset(&ifib, 0, sizeof(ifib));
	h_proto = eth->h_proto;
	if (h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS;
	}

	iph = data + nh_off;

	if (iph + 1 > data_end) {
		return XDP_DROP;
	}

	daddr = iph->daddr;

	pitem = bpf_map_lookup_elem(&rtcache_map, &daddr);
	// 首先精确查找转发表，如果找到就直接转发，不必再经历最长前缀匹配的慢速通配查找
	// 这个动作是可以offload到硬件中的。
	if (pitem) {
		__ip_decrease_ttl(iph);
		memcpy(eth->h_dest, pitem->eth_dest, ETH_ALEN);
		memcpy(eth->h_source, pitem->eth_source, ETH_ALEN);
		bpf_printk("%s----daddr : %d prot:%d",fast_info,daddr,pitem->ifindex);
		//bpf_trace_printk(fast_info, sizeof(fast_info), pitem->ifindex);
		action = bpf_redirect(pitem->ifindex, 0);
		goto out;
	}

	// 否则只能执行最长前缀匹配了
	ifib.family = AF_INET;
	ifib.tos = iph->tos;
	ifib.l4_protocol = iph->protocol;
	ifib.tot_len = bpf_ntohs(iph->tot_len);
	ifib.ipv4_src = iph->saddr;
	ifib.ipv4_dst = iph->daddr;
	ifib.ifindex = ctx->ingress_ifindex;

	// 调用eBPF封装的路由查找函数，虽然所谓慢速查找，也依然不会进入协议栈的。
	if (bpf_fib_lookup(ctx, &ifib, sizeof(ifib), 0) == 0) {
		struct rt_item_tab nitem;

		__builtin_memset(&nitem, 0, sizeof(nitem));
		memcpy(&nitem.eth_dest, ifib.dmac, ETH_ALEN);
		memcpy(&nitem.eth_source, ifib.smac, ETH_ALEN);
		nitem.ifindex = ifib.ifindex;
		// 插入新的表项
		bpf_map_update_elem(&rtcache_map, &daddr, &nitem, BPF_ANY);
		__ip_decrease_ttl(iph);
		memcpy(eth->h_dest, ifib.dmac, ETH_ALEN);
		memcpy(eth->h_source, ifib.smac, ETH_ALEN);
		bpf_printk("%s----daddr : %d prot:%d",slow_info,daddr,nitem.ifindex);
		//bpf_trace_printk(slow_info, sizeof(slow_info), ifib.ifindex);
		action = bpf_redirect(ifib.ifindex, 0);
		goto out;
	}
	action = XDP_PASS;
out:
	return xdp_stats_record_action(ctx, action);
}

static inline
void extract_key4_from_msg(struct sk_msg_md *msg, struct sock_key *key)
{
    key->sip4 = msg->remote_ip4;
    key->dip4 = msg->local_ip4;
    key->family = 1;

    key->dport = (bpf_htonl(msg->local_port) >> 16);
    key->sport = FORCE_READ(msg->remote_port) >> 16;
}
static inline
void extract_key4_from_ops(struct bpf_sock_ops *ops, struct sock_key *key)
{
    // keep ip and port in network byte order
    key->dip4 = ops->remote_ip4;
    key->sip4 = ops->local_ip4;
    key->family = 1;

    // local_port is in host byte order, and remote_port is in network byte order
    key->sport = (bpf_htonl(ops->local_port) >> 16);
    key->dport = FORCE_READ(ops->remote_port) >> 16;
}
static inline
void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
    struct sock_key key = {};
    int ret;

    extract_key4_from_ops(skops, &key);
	ret = bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
    //ret = sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
    if (ret != 0) {
        bpf_printk("sock_hash_update() failed, ret: %d\n", ret);
    }

    bpf_printk("sockmap: op %d, port %d --> %d\n", skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
}

SEC("sockops") // 加载到 ELF 中的 `sockops` 区域，有 socket operations 时触发执行
int bpf_sockmap(struct bpf_sock_ops *skops)
{
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: // 被动建连
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:  // 主动建连
            if (skops->family == 2) {             // AF_INET
                bpf_sock_ops_ipv4(skops);         // 将 socket 信息记录到到 sockmap
            }
            break;
        default:
            break;
    }
    return 0;
}
SEC("sk_msg") // 加载目标文件（ELF ）中的 `sk_msg` section，`sendmsg` 系统调用时触发执行
int bpf_redir(struct sk_msg_md *msg)
{
    struct sock_key key = {};
    extract_key4_from_msg(msg, &key);
    bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
	bpf_printk("bpf_msg_redirect_hash successful!");
    return SK_PASS;
}
char _license[] SEC("license") = "GPL";