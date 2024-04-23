#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "tcp_win.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile int filter_dport = 0;
const volatile int filter_sport = 0;
const volatile int sampling = 0;

#define FILTER_DPORT if(filter_dport){if (lport != filter_dport) { return 0; }}
#define FILTER_SPORT if(filter_sport){if (dport != filter_sport) { return 0; }}

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_established, struct sock *sk){
    struct tcp_sock *tp =(struct tcp_sock *)sk;
    
    u32 snd_cwnd = BPF_CORE_READ(tp,snd_cwnd);  //tp->snd_cwnd
    u32 snd_ssthresh = BPF_CORE_READ(tp,snd_ssthresh);//tp->snd_ssthresh
    u32 sndbuf = BPF_CORE_READ(sk,sk_sndbuf);//sk->sk_sndbuf
    u32 sk_wmem_queued = BPF_CORE_READ(sk,sk_wmem_queued);//sk->sk_wmem_queued


    u16 lport = BPF_CORE_READ(sk,__sk_common.skc_num); //sk->__sk_common.skc_num
    u16 dport = BPF_CORE_READ(sk,__sk_common.skc_dport); //sk->__sk_common.skc_dport
    //u32 state = BPF_CORE_READ(sk,sk_state); //sk->sk_state
    u32 saddr = BPF_CORE_READ(sk,__sk_common.skc_rcv_saddr); //sk->__sk_common.skc_rcv_saddr
    u32 daddr = BPF_CORE_READ(sk,__sk_common.skc_daddr); //sk->__sk_common.skc_daddr

    FILTER_DPORT
    FILTER_SPORT

    struct cwnd_data *data;
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
        if (!data)
            return 0;
    data->saddr = saddr;
    data->daddr = daddr;
    data->lport = lport;
    data->dport = __bpf_ntohs(dport);
    //data->state = state;
    data->snd_cwnd=snd_cwnd;
    data->snd_ssthresh=snd_ssthresh;
    data->sndbuf=sndbuf;
    data->sk_wmem_queued=sk_wmem_queued;

    bpf_ringbuf_submit(data, 0);
    return 0;
}