#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "port_tracing.h"
#define AF_INET 2
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");
//存储进程id与端口号关系
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10800);
	__type(key,int);
	__type(value, struct port_tracing);
} port_map SEC(".maps");
//存储进程id与流量关系
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10800);
	__type(key,int);
	__type(value, int);
} port_flow_map SEC(".maps");
struct port_tracing{
     unsigned int port;
     unsigned int sadder;
     unsigned int dadder;
};

const volatile int filter_sport = 0;

#define FILTER_SPORT if(filter_sport){if (sp.port != filter_sport) { return 0; }}

SEC("kprobe/tcp_sendmsg")
int trace_sys_send(struct pt_regs *ctx)
{
    u16 port_tmp=0;
    int ret=0;
    struct port_tracing sp={};
    struct sock *sock = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    u16 family = BPF_CORE_READ(sock,__sk_common.skc_family);
    sp.port=BPF_CORE_READ(sock,__sk_common.skc_num);
    sp.sadder=BPF_CORE_READ(sock, __sk_common.skc_rcv_saddr);//源ip
    sp.dadder = BPF_CORE_READ(sock, __sk_common.skc_daddr);//目的ip
    u16 dport = BPF_CORE_READ(sock, __sk_common.skc_dport);
    FILTER_SPORT;
    if(family == AF_INET)
    {
        if(!(sp.port))
        {//获取端口号

           return 0;
        }
        int pid=bpf_get_current_pid_tgid();
        bpf_map_update_elem(&port_map, &pid,&sp, BPF_ANY);
    }

    return 0;
}
SEC("kretprobe/tcp_sendmsg")
int trace_sys_send_ret(struct pt_regs *ctx)
{
    int pid=bpf_get_current_pid_tgid();
    int ret=0;
    u64 sum=0;

    //根据pid查找哈希表中的端口号
    struct port_tracing *st=bpf_map_lookup_elem(&port_map,&pid);
    if(!st)
    {
        return 0;
    }
    bpf_map_delete_elem(&port_map,&pid);
    u64 size=PT_REGS_RC(ctx);
    if(size>0)
    {
        //更新流量值
        int *flow_ptr=bpf_map_lookup_elem(&port_flow_map,&pid);
    
        if(!flow_ptr)
        {
            sum = size;
         //   return 0;
        } else{
            sum = *flow_ptr + size;
        }
        
        bpf_map_update_elem(&port_flow_map,&pid,&sum,BPF_ANY);
    }
    
    struct cwnd_data *data;
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
        if (!data)
            return 0;
        data->pid = pid;
        bpf_get_current_comm(&(data->comm),sizeof(data->comm));
        data->sum=sum;
        data->port=st->port;
        data->dadder=st->dadder;
        data->sadder=st->sadder;
        bpf_ringbuf_submit(data, 0);
        return 0;
}