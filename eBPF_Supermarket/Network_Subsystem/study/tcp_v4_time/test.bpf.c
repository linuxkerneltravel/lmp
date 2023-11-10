#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "test.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10800);
	__type(key,int);
	__type(value, int);
} out_timestamps SEC(".maps");
static struct tcp_sock *tcp_sk(const struct sock *sk) {
    return (struct tcp_sock *)sk;
}
SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv)
{
    int pid=bpf_get_current_pid_tgid();
    int time=bpf_ktime_get_ns()/1000;
    int err = bpf_map_update_elem(&out_timestamps, &pid,&time, BPF_ANY);
    return 0;
    

}
SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(tcp_v4_do_rcv,struct sock *sk,struct sk_buff *skb)
{

    int pid=bpf_get_current_pid_tgid();
    int sk_rx=BPF_CORE_READ(skb,mac_len);
   // struct tcp_sock *tp = tcp_sk(sk);//套接字信息
    struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);//数据包信息
    u32 start_seq = BPF_CORE_READ(tcb, seq);//开始序列号
    u32 end_seq = BPF_CORE_READ(tcb, end_seq);//结束序列号
    int end_time=bpf_ktime_get_ns()/1000;
    struct cwnd_data *data;
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
         if (!data)
            return 0;
    int *start_time;
    start_time=bpf_map_lookup_elem(&out_timestamps,&pid);
    if(start_time)
    {
         int current_time=end_time-*start_time;
         data->current_time=current_time;
    }
    data->pid=pid;
    data->start_seq=start_seq;
    data->end_seq=end_seq;
    bpf_ringbuf_submit(data, 0);
    return 0;
}