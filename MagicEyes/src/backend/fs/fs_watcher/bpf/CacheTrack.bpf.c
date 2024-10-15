#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 1024);
// 	__type(key, char[30] );
// 	__type(value,struct event_CacheTrack);
// } data SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 1024);
// 	__type(key, u64 );
// 	__type(value,struct event_CacheTrack);
// } unique_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("tracepoint/writeback/writeback_dirty_inode_start")
int trace_writeback_start(struct trace_event_raw_writeback_dirty_inode_template  *ctx){
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    struct event_CacheTrack event_info ={};
    char name[32];

    event_info.ino = ctx->ino;

    event_info.state = ctx->state;

    event_info.flags = ctx->flags;

    event_info.time = timestamp;

    // bpf_probe_read(name, sizeof(name), ctx->name);  // 从 ctx 复制设备名称

    // 检查 name 是否为空字符串
    // if (name[0] == '\0') {
    //     return 0;
    // }
    // if(name == NULL)
    //     return 0;

    // __builtin_memcpy(event_info.name, name, sizeof(name));
    // bpf_printk("comm_123:%s\n",event_info.name);

    struct event_CacheTrack *ring_event = bpf_ringbuf_reserve(&rb, sizeof(struct event_CacheTrack), 0);
    if (!ring_event)
        return 0;

    __builtin_memcpy(ring_event, &event_info, sizeof(event_info));

    bpf_printk("event_info_ino:%d\n",event_info.ino);

    bpf_ringbuf_submit(ring_event, 0);


    // bpf_map_update_elem(&data,name,&event_info,BPF_ANY);
    // bpf_map_update_elem(&unique_map,&event_info.queue_id,&event_info,BPF_ANY);
    return 0;
}

// SEC("tracepoint/writeback/writeback_written")
// int trace_writeback_end(struct trace_event_raw_writeback_work_class *ctx) {
//     bpf_printk("2222222\n");
//     u64 timestamp = bpf_ktime_get_ns();
//     char name[30];
//     bpf_probe_read_str(name, sizeof(name), ctx->name);  // 从 ctx 复制设备名称

//     if(name == NULL)
//         return 0;

//     bpf_printk("comm:%s\n",name);
    
//     struct event_CacheTrack *e = bpf_map_lookup_elem(&data,name);
//     if(!e){
//         bpf_printk("e failed\n");
//         return 0;
//     }


//     struct event_CacheTrack *q = bpf_map_lookup_elem(&unique_map,&e->queue_id);
//     if(!q){
//         bpf_printk("q failed\n");
//         return 0;
//     }

//     struct event_CacheTrack *q_event = bpf_ringbuf_reserve(&rb, sizeof(struct event_CacheTrack), 0);
//     if (!q_event){
//         bpf_printk("Ring buffer is full!\n");
//         return 0;
//     }

//     q_event->nr_pages = ctx->nr_pages;
//     q_event->sb_dev = ctx->sb_dev;              
//     q_event->sync_mode = ctx->sync_mode;        
//     q_event->for_kupdate = ctx->for_kupdate;    
//     q_event->range_cyclic = ctx->range_cyclic;  
//     q_event->for_background = ctx->for_background; 
//     q_event->reason = ctx->reason;                
//     q_event->cgroup_ino = ctx->cgroup_ino;      
//     q_event->time = timestamp - q->start_timestamp; 

//     bpf_printk("time:%llu\n",q_event->time);
//     bpf_printk("123\n");

//     bpf_ringbuf_submit(q_event, 0);

//     return 0;

// }