#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mmzone.h>
#include <linux/compaction.h>
#include <linux/mmzone.h>
#include <linux/nodemask.h> 
#include <linux/mm_types.h>
#include "stat.h"

BPF_RINGBUF_OUTPUT(buffer, 1);

struct alloc_context {
        struct zonelist *zonelist;
        nodemask_t *nodemask;
        struct zoneref *preferred_zoneref;
        int migratetype;
        enum zone_type high_zoneidx;
        bool spread_dirty_pages;
};

int sysstat(struct pt_regs *ctx) {
	u64 vm[60];
	struct zoneref *zf; 	
	struct alloc_context *ac;    
        struct pglist_data *pd;

        struct event *event = buffer.ringbuf_reserve(sizeof(struct event));
        if (!event) {
 	      return 1;
        }
	
	ac = (struct alloc_context *)PT_REGS_PARM4(ctx);
        pd = ac->preferred_zoneref->zone->zone_pgdat;
//lru
        bpf_probe_read_kernel(&event->anon_active, sizeof(u64), &pd->vm_stat[1]);
        bpf_probe_read_kernel(&event->anon_inactive, sizeof(u64), &pd->vm_stat[0]);
        bpf_probe_read_kernel(&event->file_inactive, sizeof(u64), &pd->vm_stat[2]);
        bpf_probe_read_kernel(&event->file_active, sizeof(u64), &pd->vm_stat[3]);
        bpf_probe_read_kernel(&event->unevictable, sizeof(u64), &pd->vm_stat[4]);
//working
        bpf_probe_read_kernel(&event->working_nodes, sizeof(u64), &pd->vm_stat[12]);
        bpf_probe_read_kernel(&event->working_refault, sizeof(u64), &pd->vm_stat[13]);
        bpf_probe_read_kernel(&event->working_activate, sizeof(u64), &pd->vm_stat[14]);
        bpf_probe_read_kernel(&event->working_restore, sizeof(u64), &pd->vm_stat[15]);
        bpf_probe_read_kernel(&event->working_nodereclaim, sizeof(u64), &pd->vm_stat[16]);
//page
        bpf_probe_read_kernel(&event->anon_isolated, sizeof(u64), &pd->vm_stat[7]);
	bpf_probe_read_kernel(&event->anon_mapped, sizeof(u64), &pd->vm_stat[17]);
        bpf_probe_read_kernel(&event->file_isolated, sizeof(u64), &pd->vm_stat[8]);
        bpf_probe_read_kernel(&event->file_mapped, sizeof(u64), &pd->vm_stat[18]);

        bpf_probe_read_kernel(&event->shmem, sizeof(u64), &pd->vm_stat[23]);

        bpf_probe_read_kernel(&event->slab_reclaimable, sizeof(u64), &pd->vm_stat[5]);
        bpf_probe_read_kernel(&event->slab_unreclaimable, sizeof(u64), &pd->vm_stat[6]);

	bpf_probe_read_kernel(&event->anon_thps, sizeof(u64), &pd->vm_stat[26]);
	bpf_probe_read_kernel(&event->pmdmapped, sizeof(u64), &pd->vm_stat[25]);

        buffer.ringbuf_submit(event, 0);

    return 0;
}
