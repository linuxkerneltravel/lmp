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

// 定义一个用于存储连接信息的哈希映射
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct conn_ipv4_key);
	__type(value, struct conn_ipv4_val);
	__uint(max_entries, MAX_CONNS);
} conn_ipv4_map SEC(".maps");


// 辅助函数，用于记录 XDP 操作统计信息
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

SEC("xdp")
int xdp_entry(struct xdp_md *ctx)
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
