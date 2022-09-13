#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <bcc/proto.h>


struct ipv4_flow_info {
    u64 init_time;
    u32 fastRe;
    u32 timeout;
    u32 last_cwnd;
    u32 max_bytes_inflight;
    u16 mss;
};
BPF_HASH(flows_info, struct sock *, struct ipv4_flow_info);
// BPF_SOCKHASH

struct ipv4_data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
    u8 state;
    u8 tcpflags;
    u32 snd_cwnd;
    u32 rcv_wnd;
    u32	total_retrans;
    u32 fastRe;
    u32 timeout;
    u64 bytes_acked;
    u64 bytes_received;
    u32 srtt;
    u64 srtt_sum;
    u32 srtt_counter;
    // flight size
    u32 packets_out;
    u64 duration;
    u32 bytes_inflight;
};
BPF_PERF_OUTPUT(ipv4_events);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb){
    return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb){
    return (struct iphdr *)(skb->head + skb->network_header);
}


int kprobe__tcp_ack(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb){
    u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET) return 0;

    u32 pid = bpf_get_current_pid_tgid();
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct ipv4_flow_info *finfo, zero = {};
    finfo = flows_info.lookup_or_init(&sk, &zero);

    char state = sk->__sk_common.skc_state;
    u32 ack, seq, snd_cwnd, srtt;
    u16 sport, dport;
    
    u8 tcpflags = ((u_int8_t *)tcp)[13];
    sport = tcp->source;
    dport = tcp->dest;
    sport = ntohs(sport);
    dport = ntohs(dport);
    seq = tcp->seq;
    seq = ntohl(seq);
    ack = tcp->ack_seq;
    ack = ntohl(ack);

    ##SAMPLING##
    ##FILTER_DPORT##
    ##FILTER_SPORT##
    
    struct ipv4_data_t data4 = {};
    data4.pid = pid;
    data4.saddr = ip->saddr;
    data4.daddr = ip->daddr;
    data4.dport = dport;
    data4.sport = sport;
    data4.seq = seq;
    data4.ack = ack;
    data4.state = state;
    data4.tcpflags = tcpflags;
    data4.snd_cwnd = tp->snd_cwnd;
    data4.rcv_wnd = tp->rcv_wnd;
    data4.bytes_acked = tp->bytes_acked;
    data4.bytes_received = tp->bytes_received;
    data4.total_retrans = tp->total_retrans;
    data4.fastRe = finfo->fastRe;
    data4.timeout = finfo->timeout;
    data4.srtt = tp->srtt_us;
    data4.srtt_counter += 1;
    data4.srtt_sum += tp->srtt_us;
    data4.packets_out = tp->packets_out;
    data4.duration = bpf_ktime_get_ns() - finfo->init_time;
    data4.bytes_inflight = tp->snd_nxt - tp->snd_una; 

    ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    return 0;
}


int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state){
    if (state == TCP_ESTABLISHED) {
        u64 ts = bpf_ktime_get_ns();
        struct tcp_sock *tp = (struct tcp_sock *)sk;
        struct ipv4_flow_info *finfo, zero = {};
        finfo = flows_info.lookup_or_init(&sk, &zero);
        finfo->init_time = ts;
        finfo->mss == tp->advmss;
    } else if (state == TCP_CLOSE) {
        flows_info.delete(&sk);
    }

    return 0;
} 

/* 在进入快速恢复阶段时，不管是基于Reno或者SACK的快速恢复，
 * 还是RACK触发的快速恢复，都将使用函数tcp_enter_recovery进入
 * TCP_CA_Recovery拥塞阶段。
 */
int kprobe__tcp_enter_recovery(struct pt_regs *ctx, struct sock *sk){
    struct ipv4_flow_info *finfo, zero = {};
    finfo = flows_info.lookup_or_init(&sk, &zero);
    finfo->fastRe += 1;

    return 0;
}


/* Enter Loss state. If we detect SACK reneging, forget all SACK information
 * and reset tags completely, otherwise preserve SACKs. If receiver
 * dropped its ofo queue, we will know this due to reneging detection.
 * 在报文的重传定时器到期时，在tcp_retransmit_timer函数中，进入TCP_CA_Loss拥塞状态。
 */
int kprobe__tcp_enter_loss(struct pt_regs *ctx, struct sock *sk){
    struct ipv4_flow_info *finfo, zero = {};
    finfo = flows_info.lookup_or_init(&sk, &zero);
    finfo->timeout += 1;

    return 0;
}
