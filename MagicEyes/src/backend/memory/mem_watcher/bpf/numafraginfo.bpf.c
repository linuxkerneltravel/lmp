#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "fraginfo.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__type(key, u64);
	__type(value, struct pgdat_info);
} nodes SEC(".maps");

SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order, int alloc_flags,
	       const struct alloc_context *ac)
{
	struct pgdat_info node_info = {};

	struct pglist_data *pgdat;

	pgdat = BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat);
	node_info.node_id = BPF_CORE_READ(pgdat, node_id);
	node_info.nr_zones = BPF_CORE_READ(pgdat, nr_zones);
	node_info.pgdat_ptr = (u64)pgdat;
	u64 key = (u64)pgdat;
    
	bpf_map_update_elem(&nodes, &key, &node_info, BPF_NOEXIST);

	return 0;
}
