#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/if_ether.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/tcp.h>
#include <net/ip.h>

struct flow_tuple {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct packet_tuple {
    u32 daddr;
    u16 dport;
    u32 seq;
    u32 ack;
};

struct ktime_info {
    u64 qdisc_time;
    u64 mac_time;
    u64 ip_time;
    u64 tcp_time;
};

struct data_t {
    u64 total_time;
    u64 qdisc_timestamp;
    u64 qdisc_time;
    u64 ip_time;
    u64 tcp_time;
    u32 saddr;
    u32 daddr;
    u32 nat_saddr;
    u16 nat_sport;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
};

BPF_HASH(flows, struct packet_tuple, struct flow_tuple);
BPF_HASH(out_timestamps, struct packet_tuple, struct ktime_info);
BPF_PERF_OUTPUT(timestamp_events);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb){
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb){
    return (struct iphdr *)(skb->head + skb->network_header);
}

static void get_pkt_tuple(struct packet_tuple *pkt_tuple, struct iphdr *ip, struct tcphdr *tcp){
    pkt_tuple->daddr = ip->daddr;
    u16 dport = tcp->dest;
    pkt_tuple->dport = ntohs(dport);
    u32 seq = tcp->seq;
    u32 ack = tcp->ack_seq;
    pkt_tuple->seq = ntohl(seq);
    pkt_tuple->ack = ntohl(ack);
} 

int kprobe____tcp_transmit_skb(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, u32 rcv_nxt){
    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct flow_tuple ftuple = {};
        struct packet_tuple pkt_tuple = {};
        struct tcp_skb_cb *tcb;

        u16 dport = sk->__sk_common.skc_dport;

        ftuple.saddr = sk->__sk_common.skc_rcv_saddr;
        ftuple.daddr = sk->__sk_common.skc_daddr;
        ftuple.sport = sk->__sk_common.skc_num;
        ftuple.dport = pkt_tuple.dport;

        pkt_tuple.daddr = sk->__sk_common.skc_daddr;
        pkt_tuple.dport = ntohs(dport);
        tcb = TCP_SKB_CB(skb);
        pkt_tuple.seq = tcb->seq; 
        pkt_tuple.ack = rcv_nxt;

        ##SAMPLING##
        ##FILTER_DPORT##
        ##FILTER_SPORT##

        flows.lookup_or_init(&pkt_tuple, &ftuple);
        struct ktime_info *tinfo, zero = {};
        if ((tinfo = out_timestamps.lookup_or_init(&pkt_tuple, &zero)) == NULL){
            return 0;
        }
        tinfo->tcp_time = bpf_ktime_get_ns();
    }
    
    return 0;
}

int kprobe__ip_queue_xmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb){
    u16 family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct packet_tuple pkt_tuple = {};
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        u16 dport;
        u32 seq, ack;
        pkt_tuple.daddr = sk->__sk_common.skc_daddr;
        dport = sk->__sk_common.skc_dport;
        pkt_tuple.dport = ntohs(dport);
        seq = tcp->seq;
        ack = tcp->ack_seq;
        pkt_tuple.seq = ntohl(seq);
        pkt_tuple.ack = ntohl(ack);

        ##SAMPLING##
        ##FILTER_DPORT##
        ##FILTER_SPORT##
        
        struct ktime_info *tinfo;
        if ((tinfo = out_timestamps.lookup(&pkt_tuple)) == NULL){
            return 0;
        }
        tinfo->ip_time = bpf_ktime_get_ns();
    }
    
    return 0;
}

int kprobe__dev_queue_xmit(struct pt_regs *ctx, struct sk_buff *skb){
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    ##SAMPLING##
    ##FILTER_DPORT##
    ##FILTER_SPORT##

    struct ktime_info *tinfo;
    if ((tinfo = out_timestamps.lookup(&pkt_tuple)) == NULL){
        return 0;
    }
    tinfo->mac_time = bpf_ktime_get_ns();
    return 0;
}

int kprobe__dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *skb){
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    ##SAMPLING##
    ##FILTER_DPORT##
    ##FILTER_SPORT##
    
    struct flow_tuple *ftuple;
    if((ftuple = flows.lookup(&pkt_tuple)) == NULL){
        return 0;
    }
 
    struct ktime_info *tinfo;
    if ((tinfo = out_timestamps.lookup(&pkt_tuple)) == NULL){
        return 0;
    }
    
    u16 sport = 0;
    sport = tcp->source;
    tinfo->qdisc_time = bpf_ktime_get_ns();
    struct data_t data = {};
    data.total_time = tinfo->qdisc_time - tinfo->tcp_time;
    data.qdisc_timestamp = tinfo->qdisc_time;
    data.qdisc_time = tinfo->qdisc_time - tinfo->mac_time;
    data.ip_time = tinfo->mac_time - tinfo->ip_time;
    data.tcp_time = tinfo->ip_time - tinfo->tcp_time;
    data.saddr = ftuple->saddr;
    data.daddr = pkt_tuple.daddr;
    data.nat_saddr = ip->saddr;
    data.nat_sport = ntohs(sport);
    data.sport = ftuple->sport;
    data.dport = pkt_tuple.dport;
    data.seq = pkt_tuple.seq;
    data.ack = pkt_tuple.ack;
    
    flows.delete(&pkt_tuple);
    out_timestamps.delete(&pkt_tuple);
    timestamp_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}