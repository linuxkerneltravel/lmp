#include <uapi/linux/ptrace.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <net/inet_sock.h>

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u64 ts_us;
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 ip;
    u8 state;
    u8 reason;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u64 ts_us;
    u32 pid;
    u16 sport;
    u16 dport;
    u8 ip;
    u8 state;
    u8 reason;
    char task[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv6_events);

BPF_HASH(sock_stores, u32, struct sock *);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb) {
    return (struct tcphdr *)(skb->head + skb->transport_header);
}


int kprobe__tcp_validate_incoming(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {

	u32 pid = bpf_get_current_pid_tgid();
    ##FILTER_PID##

    u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    ##FILTER_FAMILY##

    struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);
    u32 start_seq, end_seq;
    bpf_probe_read_kernel(&start_seq, sizeof(start_seq), &tcb->seq);
    bpf_probe_read_kernel(&end_seq, sizeof(end_seq), &tcb->end_seq);

    struct tcp_sock *tp = tcp_sk(sk);
    u32 rcv_wup, rcv_nxt, rcv_wnd;
    bpf_probe_read_kernel(&rcv_wup, sizeof(rcv_wup), &tp->rcv_wup);
    bpf_probe_read_kernel(&rcv_nxt, sizeof(rcv_nxt), &tp->rcv_nxt);
    bpf_probe_read_kernel(&rcv_wnd, sizeof(rcv_wnd), &tp->rcv_wnd);

    u32 receive_window = tp->rcv_wup + tp->rcv_wnd - tp->rcv_nxt;
    if(receive_window<0) receive_window=0;

    if(end_seq>=rcv_wup && rcv_nxt+receive_window>=start_seq){
        return 0;
    }
    
    u16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid=pid, .ip=4, .reason=0};
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data4.saddr, sizeof(data4.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&data4.daddr, sizeof(data4.daddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&data4.sport, sizeof(data4.sport), &sk->__sk_common.skc_num);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        data4.state = sk->__sk_common.skc_state;
        data4.dport = ntohs(dport);
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));

    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid=pid, .ip=6, .reason=0};
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.sport, sizeof(data6.sport), &sk->__sk_common.skc_num);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        data6.state = sk->__sk_common.skc_state;
        data6.dport = ntohs(dport);
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }

	return 0;
};



int kprobe__tcp_v4_do_rcv(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
	##FILTER_FAMILY6##
    u32 pid = bpf_get_current_pid_tgid();
    ##FILTER_PID##

	// stash the sock ptr for lookup on return
	sock_stores.update(&pid, &sk);
	return 0;
};

int kprobe__tcp_v6_do_rcv(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
	##FILTER_FAMILY4##
    u32 pid = bpf_get_current_pid_tgid();
    ##FILTER_PID##

	// stash the sock ptr for lookup on return
	sock_stores.update(&pid, &sk);
	return 0;
};

int kretprobe____skb_checksum_complete(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();
    ##FILTER_PID##

	struct sock **skpp;
	skpp = sock_stores.lookup(&pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	if (ret == 0) {
		sock_stores.delete(&pid);
		return 0;
	}

    // pull in details
    struct sock *sk = *skpp;
    u16 family, dport;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    ##FILTER_FAMILY##
    bpf_probe_read_kernel(&dport, sizeof(dport),&sk->__sk_common.skc_dport);

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {.pid=pid, .ip=4, .reason=2};
        data4.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data4.saddr, sizeof(data4.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&data4.daddr, sizeof(data4.daddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&data4.sport, sizeof(data4.sport), &sk->__sk_common.skc_num);
        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        data4.state = sk->__sk_common.skc_state;
        data4.dport = ntohs(dport);
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {.pid = pid, .ip=6, .reason=2};
        data6.ts_us = bpf_ktime_get_ns() / 1000;
        bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&data6.sport, sizeof(data6.sport), &sk->__sk_common.skc_num);
        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        data6.state = sk->__sk_common.skc_state;
        data6.dport = ntohs(dport); 
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    return 0;
}

// int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
//     ##FILTER_FAMILY6##
//     u32 pid = bpf_get_current_pid_tgid();
//     ##FILTER_PID##

//     // sock_stores.update(&pid, &sk);

//     // struct tcphdr *th = (const struct tcphdr *)skb->data;
//     struct tcphdr *th = skb_to_tcphdr(skb);
//     u8 tcp_doff = ((u_int8_t *)th)[12] >> 4;
// 	if (tcp_doff >= sizeof(struct tcphdr)/4) {
//         return 0;
//     }

//     bpf_trace_printk("tcp header: ");
//     for(int i=0;i<20;i++){
//         bpf_trace_printk("%d ", ((u_int8_t *)(skb->head + skb->transport_header))[i]);
//     }
//     bpf_trace_printk("\n");

//     u16 dport;
//     bpf_probe_read_kernel(&dport, sizeof(dport),&sk->__sk_common.skc_dport);

//     struct ipv4_data_t data4 = {.pid=pid, .ip=4, .reason=1};
//     data4.ts_us = bpf_ktime_get_ns() / 1000;
//     bpf_probe_read_kernel(&data4.saddr, sizeof(data4.saddr), &sk->__sk_common.skc_rcv_saddr);
//     bpf_probe_read_kernel(&data4.daddr, sizeof(data4.daddr), &sk->__sk_common.skc_daddr);
//     bpf_probe_read_kernel(&data4.sport, sizeof(data4.sport), &sk->__sk_common.skc_num);
//     bpf_get_current_comm(&data4.task, sizeof(data4.task));
//     data4.state = sk->__sk_common.skc_state;
//     data4.dport = ntohs(dport); 
//     ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
// }

// int kprobe__tcp_v6_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
//     ##FILTER_FAMILY4##
//     u32 pid = bpf_get_current_pid_tgid();
//     ##FILTER_PID##

//     // sock_stores.update(&pid, &sk);

//     struct tcphdr *th = (const struct tcphdr *)skb->data;
//     u8 tcp_doff = ((u_int8_t *)th)[12] >> 4;
// 	if (!(tcp_doff < sizeof(struct tcphdr)/4)) {
//         return 0;
//     }    

//     u16 dport;
//     bpf_probe_read_kernel(&dport, sizeof(dport),&sk->__sk_common.skc_dport);

//     struct ipv6_data_t data6 = {.pid=pid, .ip=6, .reason=1};
//     data6.ts_us = bpf_ktime_get_ns() / 1000;
//     bpf_probe_read_kernel(&data6.saddr, sizeof(data6.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
//     bpf_probe_read_kernel(&data6.daddr, sizeof(data6.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
//     bpf_probe_read_kernel(&data6.sport, sizeof(data6.sport), &sk->__sk_common.skc_num);
//     bpf_get_current_comm(&data6.task, sizeof(data6.task));
//     data6.state = 1; // sk->__sk_common.skc_state;
//     data6.dport = ntohs(dport); 
//     ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
// }