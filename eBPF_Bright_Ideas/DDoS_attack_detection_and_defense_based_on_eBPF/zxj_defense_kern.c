#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"


#define NORMAL	0
#define ATTACK	1	
#define HIGH_ACCESS	2
#define RANDOM	3
#define FIX	4

#define PIN_GLOBAL_NS		2

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

struct packet {
	unsigned int src;
	unsigned int dst;
	unsigned short l3proto;
	unsigned short l4proto;
	unsigned short sport;
	unsigned short dport;
};

struct bpf_elf_map SEC("maps") map_xdp_one = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__u32),
	.size_value = sizeof(__u16),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 4096,
};

struct bpf_elf_map SEC("maps") map_xdp_two = {
	.type = BPF_MAP_TYPE_HASH,
	.size_key = sizeof(__u32),
	.size_value = sizeof(__u16),
	.pinning = PIN_GLOBAL_NS,
	.max_elem = 4096,
};

SEC("xdp1")
int prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct packet p = {};
	u32 lookup_addr;
	u16 *value;
	u8 flags;

	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_DROP;
	}

	p.l3proto = bpf_htons(eth->h_proto);
	if (p.l3proto == ETH_P_IP) {
		struct iphdr *iph;

		iph = data + sizeof(struct ethhdr);
		if (iph + 1 > data_end)
			return XDP_DROP;

		p.src = iph->saddr;
		p.dst = iph->daddr;
		p.l4proto = iph->protocol;
		p.sport = p.dport = 0;
		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcph;
			tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			if (tcph + 1 > data_end)
				return XDP_DROP;

			p.sport = tcph->source;
			p.dport = tcph->dest;
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udph;
			udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			if (udph + 1 > data_end)
				return XDP_DROP;

			p.sport = udph->source;
			p.dport = udph->dest;
		}
	}


	lookup_addr = p.src;

	value = bpf_map_lookup_elem(&map_xdp_one, &lookup_addr);	
	if (value)
		return XDP_DROP;

	value = bpf_map_lookup_elem(&map_xdp_two, &lookup_addr);

	if (value)
		return XDP_DROP;

	lookup_addr = 0;
	value = bpf_map_lookup_elem(&map_xdp_one, &lookup_addr);
	if (value)
		flags = *value;

	if (flags != ATTACK)
		return XDP_PASS;
	else {
		;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
