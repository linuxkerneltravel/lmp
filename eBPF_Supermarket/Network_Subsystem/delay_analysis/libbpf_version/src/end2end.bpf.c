#include "vmlinux.h"
#include "maps.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "end2end.h"

#define FILTER_SPORT if(filter_sport){if (__bpf_ntohs(BPF_CORE_READ(tcp,source)) != filter_sport) { return 0; }}
#define FILTER_DPORT if(filter_dport){if (__bpf_ntohs(BPF_CORE_READ(tcp,dest)) != filter_dport) { return 0; }}

#define TCP_SKB_CB(__skb)	(struct tcp_skb_cb *)(&(__skb)->cb[0])

#define MARK_KFUNC_TIME(kfunc_name,kunc_name_quot,kfunc_id,checkip,checktcp,notify) \
SEC("kprobe/"kunc_name_quot) \
int BPF_KPROBE(kfunc_name,struct sk_buff *skb){ \
    if (skb == NULL){ \
        return 0; \
    } \
    if(checkip){ \
        struct ethhdr *eth = skb_to_ethhdr(skb); \
        if(BPF_CORE_READ(eth,h_proto) != __bpf_htons(ETH_P_IP)) \
            return 0; \
    } \
    struct iphdr *ip = skb_to_iphdr(skb); \
    if(checktcp){ \
        if(BPF_CORE_READ(ip,protocol) != IPPROTO_TCP) \
            return 0; \
    } \
    struct tcphdr *tcp = skb_to_tcphdr(skb); \
    FILTER_SPORT \
    FILTER_DPORT \
    struct packet_tuple pkt_tuple; \
    get_pkt_tuple(&pkt_tuple, ip, tcp); \
    struct pkt_time_info *p_sinfo = bpf_map_lookup_elem(&pkt_time_info_map,&pkt_tuple); \
    if(!p_sinfo) \
        return 0; \
    bpf_printk(kunc_name_quot);\
    p_sinfo->time[kfunc_id] = bpf_ktime_get_ns(); \
    if(notify){ \
        struct packet_tuple *data; \
        data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0); \
        if (!data){ \
	         return 0; \
        } \
        bpf_probe_read_kernel(data,sizeof(*data),&pkt_tuple); \
        bpf_ringbuf_submit(data, 0); \
    } \
    return 0;\
}

const volatile int filter_dport = 0;
const volatile int filter_sport = 0;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10800);
	__type(key, struct packet_tuple);
	__type(value, struct pkt_time_info);
} pkt_time_info_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static struct ethhdr *skb_to_ethhdr(const struct sk_buff *skb){
    return (struct ethhdr *)((BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,mac_header)));
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb){
    return (struct iphdr *)(BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,network_header));
}

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb){
    return (struct tcphdr *)((BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,transport_header)));
}

static void get_pkt_tuple(struct packet_tuple *pkt_tuple, struct iphdr *ip, struct tcphdr *tcp){
    pkt_tuple->saddr = BPF_CORE_READ(ip,saddr);
    pkt_tuple->daddr = BPF_CORE_READ(ip,daddr);
    u16 sport = BPF_CORE_READ(tcp,source);
    u16 dport = BPF_CORE_READ(tcp,dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    pkt_tuple->dport = __bpf_ntohs(dport);
    u32 seq = BPF_CORE_READ(tcp,seq);
    u32 ack = BPF_CORE_READ(tcp,ack_seq);
    pkt_tuple->seq = __bpf_ntohl(seq);
    pkt_tuple->ack = __bpf_ntohl(ack);
    //bpf_printk("%d,%d,%u,%u",pkt_tuple->sport,pkt_tuple->dport,pkt_tuple->seq,pkt_tuple->ack);
}

SEC("kprobe/__tcp_transmit_skb") 
int BPF_KPROBE(__tcp_transmit_skb,struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt){ 
  u16 family = BPF_CORE_READ(sk,__sk_common.skc_family);

    if (family == AF_INET) {
        struct packet_tuple pkt;
        struct pkt_time_info time_info = {};
        time_info.time[0] = bpf_ktime_get_ns();

        pkt.sport = BPF_CORE_READ(sk,__sk_common.skc_num);
        pkt.dport = __bpf_ntohs(BPF_CORE_READ(sk,__sk_common.skc_dport));
        if ((filter_sport != 0 && filter_sport != pkt.sport) || (filter_dport != 0 && filter_dport != pkt.dport)) { 
            return 0; 
        }

        pkt.saddr = BPF_CORE_READ(sk,__sk_common.skc_rcv_saddr);
        pkt.daddr = BPF_CORE_READ(sk,__sk_common.skc_daddr);

        struct tcp_skb_cb *tcb;
        tcb = TCP_SKB_CB(skb);
        pkt.seq = BPF_CORE_READ(tcb,seq);
        pkt.ack = rcv_nxt;
        bpf_printk("%d,%d,%u,%u",pkt.sport,pkt.dport,pkt.seq,pkt.ack);
        bpf_map_update_elem(&pkt_time_info_map, &pkt, &time_info, BPF_ANY);
    }
    
    return 0;
}

MARK_KFUNC_TIME(eth_type_trans,"eth_type_trans",2,1,1,0);
MARK_KFUNC_TIME(ip_rcv_core,"ip_rcv_core",3,1,1,0);
MARK_KFUNC_TIME(tcp_v4_rcv,"tcp_v4_rcv",4,1,1,0);

MARK_KFUNC_TIME(skb_copy_datagram_iter,"skb_copy_datagram_iter",1,1,1,1);


char LICENSE[] SEC("license") = "Dual BSD/GPL";