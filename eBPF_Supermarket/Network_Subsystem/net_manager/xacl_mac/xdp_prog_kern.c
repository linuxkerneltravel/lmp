/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h" 
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"



#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct datarec);
	__uint(max_entries, XDP_ACTION_MAX);
} xdp_stats_map SEC(".maps");

/*filter-pass-drop*/
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, ETH_ALEN);
	__type(value, __u32);
	__uint(max_entries, MAX_RULES);
} src_macs SEC(".maps");


static __always_inline
__u32 xdp_stats_record_action(struct xdp_md *ctx, __u32 action)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	if (action >= XDP_ACTION_MAX)
		return XDP_ABORTED;

	/* Lookup in kernel BPF-side return pointer to actual data record */
	struct datarec *rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
		return XDP_ABORTED;

	/* Calculate packet length */
	__u64 bytes = data_end - data;

	/* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
	 * CPU and XDP hooks runs under Softirq, which makes it safe to update
	 * without atomic operations.
	 */
	rec->rx_packets++;
	rec->rx_bytes += bytes;

	return action;
}


/* accept ethernet addresses and filter everything else */
SEC("xdp")
int filter_ethernet_filter(struct xdp_md *ctx)
{
	xdp_act action = XDP_PASS; 
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	int nh_type; //next header type
	struct ethhdr *eth;
	__u32 *value;


	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if(nh_type < 0)
		goto out;

	//action = match_rules_ipv4(&eth->h_source);

	/* check if src mac is in src_macs map */
	value = bpf_map_lookup_elem(&src_macs, eth->h_source);
	if (value) {
        action = *value;
		goto out;
    }
	

out:
	return xdp_stats_record_action(ctx, action);
}


