/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h" 
#include "../common/parsing_helpers.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct rules_ipv4);
	__uint(max_entries, MAX_RULES);
} rules_ipv4_map SEC(".maps");


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
	#ifdef KERNEL_5_17
	bpf_loop(MAX_RULES, match_rules_ipv4_loop, &ctx, 0);
	#endif
	#ifdef KERNEL_5_10
	#pragma unroll
	for(int i=0; i<MAX_RULES; i++){
		if(match_rules_ipv4_loop(i,&ctx))
			break;
	}
	#endif
	return ctx.action;
}

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
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

char _license[] SEC("license") = "GPL";
