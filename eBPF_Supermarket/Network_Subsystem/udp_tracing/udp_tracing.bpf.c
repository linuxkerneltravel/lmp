#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "udp_tracing.h"
#define AF_INET 2
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 10800);
	__type(key, int);
	__type(value, struct udp_tracing);
} udp_flow_map SEC(".maps");

struct udp_tracing{
     unsigned int dport;
     unsigned int sport;
     unsigned int saddr;
     unsigned int daddr;
     unsigned long long send;
     unsigned long long recv;
};

const volatile int filter_sport = 0;

#define FILTER_SPORT if(filter_sport){if (sp.port != filter_sport) { return 0; }}
//kprobe 挂载 udp_sendmsg 函数
SEC("kprobe/udp_sendmsg")
int trace_sys_send(struct pt_regs *ctx)
{
    unsigned int pid=bpf_get_current_pid_tgid();;//获取当前进程pid
    u64 tmp =PT_REGS_PARM3_CORE(ctx);//
    //struct sock *sock = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    struct udp_tracing *st=bpf_map_lookup_elem(&udp_flow_map,&pid);//使用bpf_map_lookup_elem函数查找udp_flow_map中以pid为键的元素
    if(st&&tmp>0)//如果找到对应的元素
    {
        st->send+=tmp;//累加
    }
    else{
        struct udp_tracing val = {.send = tmp, .recv = 0};
        //bpf_map_update_elem函数将以key为键、recv为值的元素插入到udp_flow_map中,进行更新
        bpf_map_update_elem(&udp_flow_map,&pid,&val,BPF_ANY);
    }
    return 0;
}

SEC("kprobe/udp_recvmsg")
int trace_sys_recv(struct pt_regs *ctx)
{
    unsigned int pid=bpf_get_current_pid_tgid();
      //查找pid关联的值
    struct udp_tracing *st=bpf_map_lookup_elem(&udp_flow_map,&pid);
    if(!st)
    {
        return 0;
    } 
    struct sock *sock = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    st->daddr = BPF_CORE_READ(sock, __sk_common.skc_daddr);
    st->saddr = BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);
    st->sport = BPF_CORE_READ(sock, __sk_common.skc_num);
    st->dport = BPF_CORE_READ(sock, __sk_common.skc_dport);
    bpf_map_update_elem(&udp_flow_map,&pid,st,BPF_ANY);
    bpf_printk("%d",st->daddr);
    return 0;
}
SEC("kretprobe/udp_recvmsg")
int trace_sys_recv_ret(struct pt_regs *ctx)
{
    unsigned int total;
    unsigned int pid=bpf_get_current_pid_tgid(); 
      //查找pid关联的值
    struct udp_tracing *st=bpf_map_lookup_elem(&udp_flow_map,&pid);
    if(!st)
    {
        return 0;
    }
    u64 tmp=PT_REGS_RC(ctx);
    if(tmp>0)
    { 
        st->recv+=tmp;     
    }
    else{ 
           struct udp_tracing val = {.send = tmp, .recv = 0};
            //bpf_map_update_elem函数将以key为键、recv为值的元素插入到udp_flow_map中,进行更新
            bpf_map_update_elem(&udp_flow_map,&pid,&val,BPF_ANY);
    }
    struct sock *sock = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    struct cwnd_data *data;
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
        if (!data)
            return 0;
        data->pid = pid;
        bpf_get_current_comm(&(data->comm),sizeof(data->comm));
        data->saddr=st->saddr;
        data->daddr=st->daddr;
        data->sport=st->sport;
        data->dport= st->dport;
        data->send=st->send;
        data->recv=st->recv;
        data->total=st->send+st->recv;
        bpf_ringbuf_submit(data, 0);
    return 0;
}
