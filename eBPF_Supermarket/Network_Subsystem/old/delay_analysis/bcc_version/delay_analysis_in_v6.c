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


struct packet_tuple {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
};

struct ktime_info {
    u64 mac_time;
    u64 ip_time;
    u64 tcp_time;
    u64 app_time;
};

struct data_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 total_time;
    u64 mac_timestamp;
    u64 mac_time;
    u64 ip_time;
    u64 tcp_time;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
};

BPF_HASH(in_timestamps, struct packet_tuple, struct ktime_info);
BPF_PERF_OUTPUT(timestamp_events);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb){
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct ipv6hdr *skb_to_ipv6hdr(const struct sk_buff *skb){
    return (struct ipv6hdr *)(skb->head + skb->network_header);
}


static void get_pkt_tuple(struct packet_tuple *pkt_tuple, struct ipv6hdr *ip6h, struct tcphdr *tcp){
    bpf_probe_read_kernel(&pkt_tuple->saddr, sizeof(pkt_tuple->saddr), &ip6h->saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&pkt_tuple->daddr, sizeof(pkt_tuple->daddr), &ip6h->daddr.in6_u.u6_addr32);
    u16 sport = tcp->source;
    u16 dport = tcp->dest;
    pkt_tuple->sport = ntohs(sport);
    pkt_tuple->dport = ntohs(dport);
    u32 seq = tcp->seq;
    u32 ack = tcp->ack_seq;
    pkt_tuple->seq = ntohl(seq);
    pkt_tuple->ack = ntohl(ack);
} 

int kprobe__eth_type_trans(struct pt_regs *ctx, struct sk_buff *skb){
    const struct ethhdr* eth = (struct ethhdr*) skb->data;
    u16 protocol = eth->h_proto;

    if (protocol == 0xDD86){ // Protocol is IPv6
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(skb->data + 14);
        struct tcphdr *tcp = (struct tcphdr *)(skb->data + sizeof(struct ipv6hdr)+14);

        struct packet_tuple pkt_tuple = {};
        get_pkt_tuple(&pkt_tuple, ip6h, tcp);
        
        ##SAMPLING##
        ##FILTER_DPORT##
        ##FILTER_SPORT##

        struct ktime_info *tinfo, zero={}; 
        if ((tinfo = in_timestamps.lookup_or_try_init(&pkt_tuple, &zero)) == NULL){
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns();
    }

    return 0;
}

int kernel_kprobe_ip6_rcv_core(struct pt_regs *ctx, struct sk_buff *skb){
    if (skb == NULL){
        return 0;
    }
    
    struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip6h, tcp);

    ##SAMPLING##
    ##FILTER_DPORT##
    ##FILTER_SPORT##

    struct ktime_info *tinfo;
    if ((tinfo = in_timestamps.lookup(&pkt_tuple)) == NULL){
        return 0;
    }
    
    tinfo->ip_time = bpf_ktime_get_ns();
    
    return 0;
}


int kprobe__tcp_v6_rcv(struct pt_regs *ctx, struct sk_buff *skb){
    if (skb == NULL)
        return 0;
    struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip6h, tcp);

    ##SAMPLING##
    ##FILTER_DPORT##
    ##FILTER_SPORT##

    struct ktime_info *tinfo;
    if ((tinfo = in_timestamps.lookup(&pkt_tuple)) == NULL){
        return 0;
    }
    tinfo->tcp_time = bpf_ktime_get_ns();
    
    return 0;
}

int kprobe__skb_copy_datagram_iter(struct pt_regs *ctx, struct sk_buff *skb){
    if (skb == NULL)
        return 0;
    struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip6h, tcp);

    ##SAMPLING##
    ##FILTER_DPORT##
    ##FILTER_SPORT##
    
    struct ktime_info *tinfo;
    if ((tinfo = in_timestamps.lookup(&pkt_tuple)) == NULL){
        return 0;
    }

    tinfo->app_time = bpf_ktime_get_ns();
    struct data_t data = {};
    data.mac_timestamp = tinfo->mac_time;
    data.total_time = tinfo->app_time - tinfo->mac_time;
    data.mac_time = tinfo->ip_time - tinfo->mac_time;
    data.ip_time = tinfo->tcp_time - tinfo->ip_time;
    data.tcp_time = tinfo->app_time - tinfo->tcp_time;

    data.saddr = pkt_tuple.saddr;
    data.daddr = pkt_tuple.daddr;
    data.sport = pkt_tuple.sport;
    data.dport = pkt_tuple.dport;
    data.seq = pkt_tuple.seq;
    data.ack = pkt_tuple.ack;
  
    in_timestamps.delete(&pkt_tuple);
    timestamp_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}