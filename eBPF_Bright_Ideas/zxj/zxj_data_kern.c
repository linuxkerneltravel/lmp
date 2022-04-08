#include <linux/ptrace.h>
#include <linux/skbuff.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include "bpf_helpers.h"

#define _(P) ({typeof(P) val; bpf_probe_read(&val, sizeof(val), &P); val;})

#define TCPHDR_FIN 0x01
#define TCPHDR_SYN 0x02
#define TCPHDR_RST 0x04
#define TCPHDR_PSH 0x08
#define TCPHDR_ACK 0x10
#define TCPHDR_URG 0x20
#define TCPHDR_ECE 0x40
#define TCPHDR_CWR 0x80

struct bpf_map_def SEC("maps") map_hash_recv = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u16),
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") map_hash_retr = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u16),
	.max_entries = 4096,
};

SEC("kprobe/tcp_v4_rcv")
int bpf_prog1(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	struct tcphdr *th;
	struct iphdr *ih;
	char *head;
	u16 transport_header;
	u16 network_header;
	u8 tcpflags;
	u8 *thp;
	u32 saddr;
	u32 key;
	u16 init_val = 1;
	u16 *value;


	skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
	head = _(skb->head);
	transport_header = _(skb->transport_header);

	th = (struct tcphdr *)(head + transport_header);
	thp = (u8 *)th + 13;
	bpf_probe_read(&tcpflags, sizeof(u8), thp);

	if ((tcpflags & TCPHDR_SYN) == 0x00)
		return 0;

	network_header = _(skb->network_header);
	ih = (struct iphdr *)(head + network_header);
	bpf_probe_read(&saddr, sizeof(u32), &(ih->saddr));

	key = saddr;
	value = bpf_map_lookup_elem(&map_hash_recv, &key);

	if (value)
		*value += 1;
	else 
		bpf_map_update_elem(&map_hash_recv, &key, &init_val, BPF_ANY);
	
	key = 0;
	value = bpf_map_lookup_elem(&map_hash_recv, &key);

	if (value)
		*value += 1;
	else 
		bpf_map_update_elem(&map_hash_recv, &key, &init_val, BPF_ANY);

	return 0;
}

struct tcp_retransmit_synack_args {
	unsigned long long pad;

	void *skaddr;
	void *req;
	__u16 sport;
	__u16 dport;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

SEC("tracepoint/tcp/tcp_retransmit_synack")
int bpf_prog2(struct tcp_retransmit_synack_args *ctx)
{
	u32 key;
	u32 daddr;
	u16 init_val = 1;
	u16 *value;

	daddr = *(u32 *)(ctx->daddr);

	key = daddr;
	value = bpf_map_lookup_elem(&map_hash_retr, &key);

	if (value)
		*value += 1;
	else 
		bpf_map_update_elem(&map_hash_retr, &key, &init_val, BPF_ANY);


	key = 0;
	value = bpf_map_lookup_elem(&map_hash_retr, &key);

	if (value)
		*value += 1;
	else 
		bpf_map_update_elem(&map_hash_retr, &key, &init_val, BPF_ANY);
	
	return 0;
}
char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
