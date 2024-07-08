/* SPDX-License-Identifier: GPL-2.0 */
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


/*filter-pass-drop*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, ETH_ALEN);
	__type(value, __u32);
	__uint(max_entries, MAX_RULES);
} src_macs SEC(".maps");


// 会话保持
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct conn_ipv4_key);
	__type(value, struct conn_ipv4_val);
	__uint(max_entries, MAX_RULES);
} conn_ipv4_map SEC(".maps");


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


/*会话保持功能*/

// 定义一个始终内联的辅助函数，用于交换连接键中的源和目的地址以及端口号
static __always_inline
int swap_conn_src_dst(struct conn_ipv4_key *conn)
{
	 // 交换源和目的 IPv4 地址
	{	
		__u32 tmp = conn->daddr;
		conn->daddr = conn->saddr;
		conn->saddr = tmp;
	}

	// 交换源和目的端口号
	{
		__u16 tmp = conn->sport;
		conn->sport = conn->dport;
		conn->dport = tmp;
	}

	return 0;
}


// 全局变量，用于循环轮询的循环计数器
int rr = 0;

// 定义一个始终内联的辅助函数，用于获取轮询循环计数器的值
static __always_inline
int get_rs_rr(){

	// 如果循环计数器超过 6，则重置为 0
	if(rr >= 6){
		rr = 0;
	}

	// 自增循环计数器并返回其当前值
	rr++;
	return rr;
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

	if( ipv4_cidr_match(p_ctx->conn->saddr, p_r->saddr, p_r->saddr_mask) && 
		ipv4_cidr_match(p_ctx->conn->daddr, p_r->daddr, p_r->daddr_mask) &&
		port_match(p_ctx->conn->sport, p_r->sport) &&
		port_match(p_ctx->conn->dport, p_r->dport) &&
		port_match(p_ctx->conn->ip_proto, p_r->ip_proto) ) 
	{
		p_ctx->action = p_r->action;
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

		conn.saddr = bpf_ntohl(iph -> saddr);
		conn.daddr = bpf_ntohl(iph -> daddr);
		conn.ip_proto = nh_type;

		#ifdef DEBUG_PRINT_EVERY
		if(conn.dport != 22)
			bpf_printk("conn(%u:%u to %u:%u)", conn.saddr, conn.sport, conn.daddr, conn.dport);
		#endif

		action = match_rules_ipv4(&conn);

	}
	
		
out:
	return xdp_stats_record_action(ctx, action);
}




/* Solution to packet03/assignment-4 */
SEC("xdp")
int xdp_entry_router(struct xdp_md *ctx)
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
	__u32 *value;


	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if(nh_type < 0)
		goto out;

	//action = match_rules_ipv4(&eth->h_source);

	/* check if src mac is in src_macs map */
	value = bpf_map_lookup_elem(&src_macs, eth->h_source);
	if (value) {
        action = *value;
		goto out;
    }
	

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

		
		// 如果下一个头部类型为TCP
		if (nh_type == IPPROTO_TCP) {
			if(parse_tcphdr(&nh, data_end, &tcph) < 0)
				goto out;
			
			// 获取TCP连接信息
			conn_k.sport = bpf_ntohs(tcph -> source);
			conn_k.dport = bpf_ntohs(tcph -> dest);
			
			// 查找IPv4连接映射表中的值
			// 如果找到，就说明该连接已经存在，可以在原有连接信息的基础上进行处理。
			// 如果没有找到，可能是首次遇到这个连接，可以进行一些初始化操作，例如创建新的连接信息并添加到哈希表中。
			struct conn_ipv4_val *p_conn_v = bpf_map_lookup_elem(&conn_ipv4_map, &conn_k);
			if(!p_conn_v){
				// 如果查找失败，交换源目地址和端口信息后再次查找
				swap_conn_src_dst(&conn_k);
				p_conn_v = bpf_map_lookup_elem(&conn_ipv4_map, &conn_k);

				// 如果再次查找失败，且TCP报文是SYN并且不是ACK，则创建新的连接项
				if(!p_conn_v){
					if(tcph->syn && !tcph->ack){
						struct conn_ipv4_val conn_v = {.tcp_state = TCP_S_SYN_SENT};
						conn_v.rid = get_rs_rr();
						swap_conn_src_dst(&conn_k);
						// 将新的连接项插入到 IPv4 连接映射中
						bpf_map_update_elem(&conn_ipv4_map, &conn_k, &conn_v, BPF_ANY);
						// 输出日志信息，表示创建了一个新的连接项
						bpf_printk("conn(%u:%u->%u:%u),state:%s,rid:%d",conn_k.saddr, conn_k.sport, conn_k.daddr, conn_k.dport, "SYN_SENT", conn_v.rid);	
					}
					goto out;
				}
			}
			// 如果查找成功，继续处理连接项
			// 如果TCP报文的标志位包含RST（复位），则删除连接项并输出相应的日志信息
			if(tcph->rst){
				bpf_map_delete_elem(&conn_ipv4_map, &conn_k);
				bpf_printk("conn(%u:%u->%u:%u),state:%s,rid:%d",conn_k.saddr, conn_k.sport, conn_k.daddr, conn_k.dport, "RST", p_conn_v->rid);
				goto out;
			}

			// 如果连接项的TCP状态为SYN_RECV并且收到了ACK，将TCP状态更新为ESTABLISHED
			if(p_conn_v->tcp_state == TCP_S_SYN_RECV && tcph->ack){
				p_conn_v->tcp_state = TCP_S_ESTABLISHED;
				goto out_tcp_conn;
			}

			// 如果连接项的TCP状态为ESTABLISHED并且收到了FIN，将TCP状态更新为FIN_WAIT1
			if(p_conn_v->tcp_state == TCP_S_ESTABLISHED && tcph->fin){
				p_conn_v->tcp_state = TCP_S_FIN_WAIT1;
				goto out_tcp_conn;
			}

			// 如果连接项的TCP状态为FIN_WAIT2并且收到了ACK，将TCP状态更新为CLOSE
			if(p_conn_v->tcp_state == TCP_S_FIN_WAIT2 && tcph->ack){
				p_conn_v->tcp_state = TCP_S_CLOSE;
				goto out_tcp_conn;
			}

			// 交换源目地址和端口信息
			swap_conn_src_dst(&conn_k);


			// 如果连接项的TCP状态为SYN_SENT且收到了SYN和ACK，将TCP状态更新为SYN_RECV
			if(p_conn_v->tcp_state == TCP_S_SYN_SENT && tcph->syn && tcph->ack){
				p_conn_v->tcp_state = TCP_S_SYN_RECV;
				goto out_tcp_conn;
			}

			// 如果连接项的TCP状态为FIN_WAIT1且收到了ACK，将TCP状态更新为CLOSE_WAIT
			if(p_conn_v->tcp_state == TCP_S_FIN_WAIT1 && tcph->ack){
				p_conn_v->tcp_state = TCP_S_CLOSE_WAIT;
				bpf_printk("conn(%u:%u->%u:%u),state:%s,rid:%d",conn_k.saddr, conn_k.sport, conn_k.daddr, conn_k.dport, "CLOSE_WAIT", p_conn_v->rid);
			}
			
			// 如果连接项的TCP状态为CLOSE_WAIT且收到了FIN和ACK，将TCP状态更新为FIN_WAIT2
			if(p_conn_v->tcp_state == TCP_S_CLOSE_WAIT && tcph->fin && tcph->ack){
				p_conn_v->tcp_state = TCP_S_FIN_WAIT2;
				goto out_tcp_conn;
			}
			const char *tcp_state_str;

			// 根据连接状态设置对应的字符串
			out_tcp_conn:
				if(p_conn_v->tcp_state == TCP_S_CLOSE){
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
				bpf_printk("conn(%u:%u->%u:%u),state:%s,rid:%d",conn_k.saddr, conn_k.sport, conn_k.daddr, conn_k.dport, tcp_state_str, p_conn_v->rid);				
				goto out;
		}
		else if(nh_type == IPPROTO_UDP){
			// 如果是UDP包，解析UDP头部并获取端口信息
			if(parse_udphdr(&nh, data_end, &udph) < 0){
				goto out;
			}
			conn_k.sport = bpf_ntohs(udph -> source);
			conn_k.dport = bpf_ntohs(udph -> dest);
		}

		#ifdef DEBUG_PRINT_EVERY
		// 打印除SSH协议以外的所有连接信息
		if(conn.dport != 22)
			bpf_printk("conn(%u:%u to %u:%u)", conn.saddr, conn.sport, conn.daddr, conn.dport);
		#endif

	}
	
		
out:
	return xdp_stats_record_action(ctx, action);
}


char _license[] SEC("license") = "GPL";