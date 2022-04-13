// +build ignore
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct skb_message {
	u64 time;
 	uint len;
 	uint data_len;

	__u16 transport_header;
	__u16 network_header;
	__u16 mac_header;
	char name[30];
}__attribute__((packed));

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1<<24,
};

struct bpf_map_def SEC("maps") pidfor_user = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") current_time = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 6,
};

SEC("kprobe/__tcp_transmit_skb")
int kprobe_tcp_transmit_skb(struct pt_regs *ctx) {
	u64 time = bpf_ktime_get_ns();
	u32 key = 0;
	bpf_map_update_elem(&current_time,&key,&time,BPF_ANY);
	return 0;
}

SEC("kprobe/__ip_queue_xmit")
int kprobe_ip_queue_xmit(struct pt_regs *ctx) {
	struct skb_message *skb_mss;
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	u64 time = bpf_ktime_get_ns();
	u32 key_time = 1;

	u64  id,*current;
	u32 *test_pid;
	id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; 
	u32 key = 0;
	// int my_pid;
    // asm("%0 = MY_PID ll" : "=r"(my_pid));
	test_pid = bpf_map_lookup_elem(&pidfor_user,&key);
	if(test_pid == NULL)
		return 0;
	if ((*test_pid) != 0)
	{
		if(pid != (*test_pid))
			return 0;
	}

	skb_mss = bpf_ringbuf_reserve(&events, sizeof(struct skb_message), 0);
	if (!skb_mss) {
		return 0;
	}
	current = bpf_map_lookup_elem(&current_time,&key);
	// if (current == NULL)
	// 	return 0;
	bpf_probe_read_kernel(&(skb_mss->name),sizeof(u64),current);
	bpf_probe_read_kernel(&(skb_mss->len),sizeof(uint),&(skb->len));
	bpf_probe_read_kernel(&(skb_mss->data_len),sizeof(uint),&(skb->data_len));
	bpf_probe_read_kernel(&(skb_mss->mac_header),sizeof(__u16),&(skb->mac_header));
	bpf_probe_read_kernel(&(skb_mss->network_header),sizeof(__u16),&(skb->network_header));
	bpf_probe_read_kernel(&(skb_mss->transport_header),sizeof(__u16),&(skb->transport_header));

	char ch[30] = "T _tcp_transmit_skb";
	bpf_probe_read_kernel(skb_mss->name,sizeof(ch),ch);
	bpf_ringbuf_submit(skb_mss, 0);
	// 更新时间
	bpf_map_update_elem(&current_time,&key,&time,BPF_ANY);

	return 0;
}

SEC("kprobe/ip_local_out")
int kprobe_ip_local_out(struct pt_regs *ctx) {
	struct skb_message *skb_mss;
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	//u64 time = bpf_ktime_get_ns();
	u32 key_time = 1;

	u64  id,*current;
	u32 *test_pid;
	id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; 
	u32 key = 0;
	test_pid = bpf_map_lookup_elem(&pidfor_user,&key);
	if(test_pid == NULL)
		return 0;
	if ((*test_pid) != 0)
	{
		if(pid != (*test_pid))
			return 0;
	}

	skb_mss = bpf_ringbuf_reserve(&events, sizeof(struct skb_message), 0);
	if (!skb_mss) {
		return 0;
	}
	current = bpf_map_lookup_elem(&current_time,&key_time);
	// if (current == NULL)
	// 	return 0;
	//skb_mss->time = *current; 
	bpf_probe_read_kernel(&(skb_mss->len),sizeof(uint),&(skb->len));
	bpf_probe_read_kernel(&(skb_mss->data_len),sizeof(uint),&(skb->data_len));
	bpf_probe_read_kernel(&(skb_mss->mac_header),sizeof(__u16),&(skb->mac_header));
	bpf_probe_read_kernel(&(skb_mss->network_header),sizeof(__u16),&(skb->network_header));
	bpf_probe_read_kernel(&(skb_mss->transport_header),sizeof(__u16),&(skb->transport_header));
	char ch[30] = "T __ip_queue_xmit";
	bpf_probe_read_kernel(skb_mss->name,sizeof(ch),ch);
	bpf_ringbuf_submit(skb_mss, 0);
	// 更新时间
	//bpf_map_update_elem(&current_time,&key_time1,&time,BPF_ANY);

	return 0;
}

SEC("kprobe/__dev_queue_xmit")
int kprobe_dev_queue_xmit(struct pt_regs *ctx) {
	struct skb_message *skb_mss;
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	//u64 time = bpf_ktime_get_ns();
	//u32 key_time = 1,key_time1 = 2;

	u64  id,*current;
	u32 *test_pid;
	id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; 
	u32 key = 0;
	test_pid = bpf_map_lookup_elem(&pidfor_user,&key);
	if(test_pid == NULL)
		return 0;
	if ((*test_pid) != 0)
	{
		if(pid != (*test_pid))
			return 0;
	}

	skb_mss = bpf_ringbuf_reserve(&events, sizeof(struct skb_message), 0);
	if (!skb_mss) {
		return 0;
	}
	// current = bpf_map_lookup_elem(&current_time,&key_time);
	// if (current == NULL)
	// 	return 0;
	skb_mss->time = bpf_ktime_get_ns(); 
	bpf_probe_read_kernel(&(skb_mss->len),sizeof(uint),&(skb->len));
	bpf_probe_read_kernel(&(skb_mss->data_len),sizeof(uint),&(skb->data_len));
	bpf_probe_read_kernel(&(skb_mss->mac_header),sizeof(__u16),&(skb->mac_header));
	bpf_probe_read_kernel(&(skb_mss->network_header),sizeof(__u16),&(skb->network_header));
	bpf_probe_read_kernel(&(skb_mss->transport_header),sizeof(__u16),&(skb->transport_header));
	char ch[] = "T __dev_queue_xmit";
	bpf_probe_read_kernel(skb_mss->name,sizeof(ch),ch);
	bpf_ringbuf_submit(skb_mss, 0);
	// 更新时间
	//bpf_map_update_elem(&current_time,&key_time1,&time,BPF_ANY);

	return 0;
}

SEC("kprobe/eth_type_trans")
int kprobe_eth_type_trans(struct pt_regs *ctx) {
	u64 time = bpf_ktime_get_ns();
	u32 key = 2;
	bpf_map_update_elem(&current_time,&key,&time,BPF_ANY);
	return 0;
}

SEC("kprobe/ip_rcv")
int kprobe_ip_rcv(struct pt_regs *ctx) {
	struct skb_message *skb_mss;
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	u64 time = bpf_ktime_get_ns();
	u32 key_time = 2,key_time1 = 3;

	u64  id,*current;
	u32 *test_pid;
	id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; 
	u32 key = 0;
	test_pid = bpf_map_lookup_elem(&pidfor_user,&key);
	if(test_pid == NULL)
		return 0;
	if ((*test_pid) != 0)
	{
		if(pid != (*test_pid))
			return 0;
	}

	skb_mss = bpf_ringbuf_reserve(&events, sizeof(struct skb_message), 0);
	if (!skb_mss) {
		return 0;
	}
	current = bpf_map_lookup_elem(&current_time,&key_time);
	// if (current == NULL)
	// 	return 0;
	//skb_mss->time = *current; 
	bpf_probe_read_kernel(&(skb_mss->len),sizeof(uint),&(skb->len));
	bpf_probe_read_kernel(&(skb_mss->data_len),sizeof(uint),&(skb->data_len));
	bpf_probe_read_kernel(&(skb_mss->mac_header),sizeof(__u16),&(skb->mac_header));
	bpf_probe_read_kernel(&(skb_mss->network_header),sizeof(__u16),&(skb->network_header));
	bpf_probe_read_kernel(&(skb_mss->transport_header),sizeof(__u16),&(skb->transport_header));
	char ch[30] = "R eth_type_trans";
	bpf_probe_read_kernel(skb_mss->name,sizeof(ch),ch);
	bpf_ringbuf_submit(skb_mss, 0);
	//更新时间:该时间将data指针指向网络头
	bpf_map_update_elem(&current_time,&key_time1,&time,BPF_ANY);

	return 0;
}

SEC("kprobe/ip_local_deliver_finish")
int kprobe_ip_local_deliver_finish(struct pt_regs *ctx)
{
	u64 time = bpf_ktime_get_ns();
	u32 key = 3;
	bpf_map_update_elem(&current_time,&key,&time,BPF_ANY);
	return 0;
}
SEC("kprobe/ip_protocol_deliver_rcu")
int kprobe_ip_protocol_deliver_rcu(struct pt_regs *ctx) {
	struct skb_message *skb_mss;
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	//u64 time = bpf_ktime_get_ns();
	u32 key_time = 3;

	u64  id,*current;
	u32 *test_pid;
	id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; 
	u32 key = 0;
	test_pid = bpf_map_lookup_elem(&pidfor_user,&key);
	if(test_pid == NULL)
		return 0;
	if ((*test_pid) != 0)
	{
		if(pid != (*test_pid))
			return 0;
	}

	skb_mss = bpf_ringbuf_reserve(&events, sizeof(struct skb_message), 0);
	if (!skb_mss) {
		return 0;
	}
	current = bpf_map_lookup_elem(&current_time,&key_time);
	// if (current == NULL)
	// 	return 0;
	//skb_mss->time = *current; 
	bpf_probe_read_kernel(&(skb_mss->len),sizeof(uint),&(skb->len));
	bpf_probe_read_kernel(&(skb_mss->data_len),sizeof(uint),&(skb->data_len));
	bpf_probe_read_kernel(&(skb_mss->mac_header),sizeof(__u16),&(skb->mac_header));
	bpf_probe_read_kernel(&(skb_mss->network_header),sizeof(__u16),&(skb->network_header));
	bpf_probe_read_kernel(&(skb_mss->transport_header),sizeof(__u16),&(skb->transport_header));
	char ch[30] = "R ip_local_deliver_finish";
	bpf_probe_read_kernel(skb_mss->name,sizeof(ch),ch);

	bpf_ringbuf_submit(skb_mss, 0);
	// 更新时间:该时间将data指针指向网络头
	// bpf_map_update_elem(&current_time,&key_time1,&time,BPF_ANY);

	return 0;
}

SEC("kprobe/tcp_rcv_established")
int kprobe_tcp_rcv_established(struct pt_regs *ctx) {
	u64 time = bpf_ktime_get_ns();
	u32 key = 4;
	bpf_map_update_elem(&current_time,&key,&time,BPF_ANY);
	return 0;
}

SEC("kprobe/tcp_data_queue")
int kprobe_tcp_data_queue(struct pt_regs *ctx) {
	struct skb_message *skb_mss;
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
	//u64 time = bpf_ktime_get_ns();
	u32 key_time = 4;

	u64  id,*current;
	u32 *test_pid;
	id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32; 
	u32 key = 0;
	test_pid = bpf_map_lookup_elem(&pidfor_user,&key);
	if(test_pid == NULL)
		return 0;
	if ((*test_pid) != 0)
	{
		if(pid != (*test_pid))
			return 0;
	}

	skb_mss = bpf_ringbuf_reserve(&events, sizeof(struct skb_message), 0);
	if (!skb_mss) {
		return 0;
	}
	current = bpf_map_lookup_elem(&current_time,&key_time);
	// if (current == NULL)
	// 	return 0;
	//skb_mss->time = *current; 
	bpf_probe_read_kernel(&(skb_mss->len),sizeof(uint),&(skb->len));
	bpf_probe_read_kernel(&(skb_mss->data_len),sizeof(uint),&(skb->data_len));
	bpf_probe_read_kernel(&(skb_mss->mac_header),sizeof(__u16),&(skb->mac_header));
	bpf_probe_read_kernel(&(skb_mss->network_header),sizeof(__u16),&(skb->network_header));
	bpf_probe_read_kernel(&(skb_mss->transport_header),sizeof(__u16),&(skb->transport_header));
	char ch[30] = "R tcp_rcv_established";
	bpf_probe_read_kernel(skb_mss->name,sizeof(ch),ch);
	
	bpf_ringbuf_submit(skb_mss, 0);

	return 0;
}