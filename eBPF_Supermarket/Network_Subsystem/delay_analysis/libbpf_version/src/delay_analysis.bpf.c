#include "vmlinux.h"
#include "maps.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "delay_analysis.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10800);
	__type(key, struct packet_tuple);
	__type(value, struct flow_tuple);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10800);
	__type(key, struct packet_tuple);
	__type(value, struct ktime_info);
} in_timestamps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10800);
	__type(key, struct packet_tuple);
	__type(value, struct ktime_info);
} out_timestamps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile int filter_dport = 0;
const volatile int filter_sport = 0;
const volatile int sampling = 0;

#define SAMPLING  if(sampling){ if (((pkt_tuple.seq + pkt_tuple.ack + BPF_CORE_READ(skb,len)) << (32-sampling) >> (32-sampling)) != ((0x01 << sampling) - 1)) { return 0;}}
#define FILTER_DPORT if(filter_dport){if (pkt_tuple.dport != filter_dport) { return 0; }}
#define FILTER_SPORT if(filter_sport){if (pkt_tuple.sport != filter_sport) { return 0; }}

#define TCP_SKB_CB(__skb)	((struct tcp_skb_cb *)(BPF_CORE_READ((__skb),cb[0])))


static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb){
    return (struct tcphdr *)((BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,transport_header)));
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb){
    return (struct iphdr *)(BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,network_header));
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
} 

SEC("kprobe/eth_type_trans")
int BPF_KPROBE(eth_type_trans, struct sk_buff *skb){
    const struct ethhdr* eth = (struct ethhdr*)BPF_CORE_READ(skb,data);
    u16 protocol = BPF_CORE_READ(eth, h_proto); 

    if (protocol == 8){ // Protocol is IP
        struct iphdr *ip = (struct iphdr *)(BPF_CORE_READ(skb,data) + 14);
        // TODO options in hdr
        struct tcphdr *tcp = (struct tcphdr *)(BPF_CORE_READ(skb,data) + 34);
        struct packet_tuple pkt_tuple = {};
        get_pkt_tuple(&pkt_tuple, ip, tcp);
        
        SAMPLING
        FILTER_DPORT
        FILTER_SPORT
        
        struct ktime_info *tinfo, zero={}; 
        
        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&in_timestamps,&pkt_tuple, &zero);
        if (tinfo == NULL){
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns();
    }

    return 0;
}

SEC("kprobe/ip_rcv_core")
int BPF_KPROBE(ip_rcv_core,struct sk_buff *skb){
    if (skb == NULL){
        return 0;
    }
    
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    SAMPLING
    FILTER_DPORT
    FILTER_SPORT

    struct ktime_info *tinfo;
    
    if ((tinfo = bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
        return 0;
    }
    
    tinfo->ip_time = bpf_ktime_get_ns();
    
    return 0;
}

SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv,struct sk_buff *skb){
    if (skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    SAMPLING
    FILTER_DPORT
    FILTER_SPORT

    struct ktime_info *tinfo;
    if ((tinfo =  bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
        return 0;
    }
    tinfo->tcp_time = bpf_ktime_get_ns();
    
    return 0;
}

SEC("kprobe/skb_copy_datagram_iter")
int BPF_KPROBE(skb_copy_datagram_iter,struct sk_buff *skb){
    if (skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    SAMPLING
    FILTER_DPORT
    FILTER_SPORT
    
    struct ktime_info *tinfo;
    if ((tinfo =  bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
        return 0;
    }

    tinfo->app_time = bpf_ktime_get_ns();

    struct data_t *data;
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if (!data)
		return 0;

    data->dir = 1;
    data->mac_timestamp = tinfo->mac_time;
    data->total_time = tinfo->app_time - tinfo->mac_time;
    data->mac_time = tinfo->ip_time - tinfo->mac_time;
    data->ip_time = tinfo->tcp_time - tinfo->ip_time;
    data->tcp_time = tinfo->app_time - tinfo->tcp_time;
    data->saddr = pkt_tuple.saddr;
    data->daddr = pkt_tuple.daddr;
    data->sport = pkt_tuple.sport;
    data->dport = pkt_tuple.dport;
    data->seq = pkt_tuple.seq;
    data->ack = pkt_tuple.ack;
    bpf_map_delete_elem(&in_timestamps,&pkt_tuple);
    bpf_ringbuf_submit(data, 0);
    return 0;
}

SEC("kprobe/__tcp_transmit_skb")
int BPF_KPROBE(__tcp_transmit_skb,struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt){
    u16 family = BPF_CORE_READ(sk,__sk_common.skc_family);

    if (family == AF_INET) {
        struct flow_tuple ftuple = {};
        struct packet_tuple pkt_tuple = {};
        struct tcp_skb_cb *tcb;

        u16 dport = BPF_CORE_READ(sk,__sk_common.skc_dport);

        ftuple.saddr = BPF_CORE_READ(sk,__sk_common.skc_rcv_saddr);
        ftuple.daddr = BPF_CORE_READ(sk,__sk_common.skc_daddr);
        ftuple.sport = BPF_CORE_READ(sk,__sk_common.skc_num);
        ftuple.dport = pkt_tuple.dport;

        pkt_tuple.daddr = BPF_CORE_READ(sk,__sk_common.skc_daddr);
        pkt_tuple.dport = __bpf_ntohs(dport);
        tcb = TCP_SKB_CB(skb);
        pkt_tuple.seq = BPF_CORE_READ(tcb,seq);
        pkt_tuple.ack = rcv_nxt;

        SAMPLING
        FILTER_DPORT
        FILTER_SPORT
        bpf_map_lookup_or_try_init(&flows,&pkt_tuple, &ftuple);
        struct ktime_info *tinfo, zero = {};
        tinfo = bpf_map_lookup_or_try_init(&out_timestamps,&pkt_tuple,&zero);
        if (tinfo == NULL){
            return 0;
        }
        tinfo->tcp_time = bpf_ktime_get_ns();
    }
    
    return 0;
}

SEC("kprobe/ip_queue_xmit")
int BPF_KPROBE(ip_queue_xmit,struct sock *sk, struct sk_buff *skb){
    u16 family = BPF_CORE_READ(sk,__sk_common.skc_family);

    if (family == AF_INET) {
        struct packet_tuple pkt_tuple = {};
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        u16 dport;
        u32 seq, ack;
        pkt_tuple.daddr = BPF_CORE_READ(sk,__sk_common.skc_daddr);
        dport = BPF_CORE_READ(sk,__sk_common.skc_dport);
        pkt_tuple.dport = __bpf_ntohs(dport);
        seq = BPF_CORE_READ(tcp, seq);
        ack = BPF_CORE_READ(tcp, ack_seq);
        pkt_tuple.seq = __bpf_ntohl(seq);
        pkt_tuple.ack = __bpf_ntohl(ack);

        SAMPLING
        FILTER_DPORT
        FILTER_SPORT
        
        struct ktime_info *tinfo;
        tinfo = bpf_map_lookup_elem(&out_timestamps,&pkt_tuple);
        if (tinfo == NULL){
            return 0;
        }
        tinfo->ip_time = bpf_ktime_get_ns();
    }
    
    return 0;
}

SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(__dev_queue_xmit,struct sk_buff *skb){
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    SAMPLING
    FILTER_DPORT
    FILTER_SPORT

    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&out_timestamps,&pkt_tuple);
    if (tinfo == NULL){
        return 0;
    }
    tinfo->mac_time = bpf_ktime_get_ns();
    return 0;
}

SEC("kprobe/dev_hard_start_xmit")
int BPF_KPROBE(dev_hard_start_xmit,struct sk_buff *skb){
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    SAMPLING
    FILTER_DPORT
    FILTER_SPORT
    
    struct flow_tuple *ftuple;
    ftuple = bpf_map_lookup_elem(&flows,&pkt_tuple);
    if(ftuple == NULL){
        return 0;
    }
 
    struct ktime_info *tinfo;
    tinfo = bpf_map_lookup_elem(&out_timestamps,&pkt_tuple);
    if (tinfo == NULL){
        return 0;
    }
    
    u16 sport = 0;
    sport = BPF_CORE_READ(tcp,source);
    tinfo->qdisc_time = bpf_ktime_get_ns();

    struct data_t *data;
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if (!data)
		return 0;
    data->dir = 0;
    data->total_time = tinfo->qdisc_time - tinfo->tcp_time;
    data->qdisc_timestamp = tinfo->qdisc_time;
    data->qdisc_time = tinfo->qdisc_time - tinfo->mac_time;
    data->ip_time = tinfo->mac_time - tinfo->ip_time;
    data->tcp_time = tinfo->ip_time - tinfo->tcp_time;
    data->saddr = ftuple->saddr;
    data->daddr = pkt_tuple.daddr;
    data->nat_saddr = BPF_CORE_READ(ip,saddr);
    data->nat_sport = __bpf_ntohs(sport);
    data->sport = ftuple->sport;
    data->dport = pkt_tuple.dport;
    data->seq = pkt_tuple.seq;
    data->ack = pkt_tuple.ack;
    
    bpf_map_delete_elem(&flows,&pkt_tuple);
    bpf_map_delete_elem(&out_timestamps,&pkt_tuple);

    bpf_ringbuf_submit(data, 0);
    return 0;
}