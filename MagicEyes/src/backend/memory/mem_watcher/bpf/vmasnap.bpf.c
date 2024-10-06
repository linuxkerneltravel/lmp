#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mem_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// BPF Map 用于存储插入操作的事件数据
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, u64);
    __type(value, struct insert_event_t);
} insert_events SEC(".maps");

// BPF Map 用于存储查找操作的事件数据
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, u64);
    __type(value, struct find_event_t);
} find_events SEC(".maps");

// ===============================
// 查找操作的 Trace 函数
// ===============================

// Trace function for vmacache_find
SEC("kprobe/vmacache_find")
int BPF_KPROBE(trace_vmacache_find, struct mm_struct *mm, unsigned long addr) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct find_event_t event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.addr = addr;
    
    // Initialize event with default values
    event.vmacache_hit = 0;

    // Update map with initial event details
    bpf_map_update_elem(&find_events, &pid, &event, BPF_ANY);
    return 0;
}

SEC("kretprobe/vmacache_find")
int BPF_KRETPROBE(trace_vmacache_find_ret) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct find_event_t *event;
    struct vm_area_struct *vma;

    // Look up the event for the current PID
    event = bpf_map_lookup_elem(&find_events, &pid);
    if (event) {
        // Check the return value of vmacache_find
        vma = (struct vm_area_struct *)PT_REGS_RC(ctx);
        if (vma) {
            // If vma is not NULL, set vmacache_hit to 1
            event->vmacache_hit = 1;
        } else {
            // If vma is NULL, set vmacache_hit to 0
            event->vmacache_hit = 0;
        }

        // Update the event in the map
        bpf_map_update_elem(&find_events, &pid, event, BPF_ANY);
    }
    return 0;
}

// Trace function for find_vma
SEC("kprobe/find_vma")
int BPF_KPROBE(trace_find_vma, struct mm_struct *mm, unsigned long addr) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct find_event_t event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.addr = addr;
    
    // Initialize event with default values
    event.vmacache_hit = 0;

    // Update map with initial event details
    bpf_map_update_elem(&find_events, &pid, &event, BPF_ANY);
    return 0;
}

SEC("kretprobe/find_vma")
int BPF_KRETPROBE(trace_find_vma_ret) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct find_event_t *event;
    struct vm_area_struct *vma;

    event = bpf_map_lookup_elem(&find_events, &pid);
    if (event) {
        event->duration = bpf_ktime_get_ns() - event->timestamp;

        // Retrieve vma and rb_subtree_last
        vma = (struct vm_area_struct *)PT_REGS_RC(ctx);
        if (vma) {
            u64 rb_subtree_last = BPF_CORE_READ(vma, shared.rb_subtree_last);
            u64 vm_start = BPF_CORE_READ(vma, vm_start);
            u64 vm_end = BPF_CORE_READ(vma, vm_end);

            event->rb_subtree_last = rb_subtree_last;
            event->vm_start = vm_start;
            event->vm_end = vm_end;
            bpf_printk("pid=%llu\n", pid);
            bpf_printk("find_vma addr=%lu, duration=%llu ns, rb_subtree_last=%llu\n",
               event->addr, event->duration, event->rb_subtree_last);
            bpf_printk("vm_start=%llu, vm_end=%llu\n",
               vm_start, vm_end);
            bpf_printk("vmacache_hit=%d\n", event->vmacache_hit);
        }
        else {
            bpf_printk("find_vma addr=%lu, duration=%llu ns, rb_subtree_last=not_available, vmacache_hit=%d\n",
                event->addr, event->duration, event->vmacache_hit);
        }

        // bpf_map_delete_elem(&find_events, &pid);
    }
    return 0;
}

// ===============================
// 插入操作的 Trace 函数
// ===============================

// Trace function for insert_vm_struct
SEC("kprobe/insert_vm_struct")
int BPF_KPROBE(trace_insert_vm_struct, struct mm_struct *mm, struct vm_area_struct *vma) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct insert_event_t event = {};
    event.timestamp = bpf_ktime_get_ns();
    
    // Initialize event with default values
    event.inserted_to_list = 0;
    event.inserted_to_rb = 0;
    event.inserted_to_interval_tree = 0;
    event.link_list_duration = 0;
    event.link_rb_duration = 0;
    event.interval_tree_duration = 0;

    // Update map with initial event details
    bpf_map_update_elem(&insert_events, &pid, &event, BPF_ANY);

    return 0;
}

// Kprobe for __vma_link_list
SEC("kprobe/__vma_link_list")
int BPF_KPROBE(trace_vma_link_list, struct mm_struct *mm, struct vm_area_struct *vma, struct vm_area_struct *prev) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    struct insert_event_t *event = bpf_map_lookup_elem(&insert_events, &pid);
    if (event) {
        event->inserted_to_list = 1;
        event->link_list_start_time = timestamp;
        bpf_map_update_elem(&insert_events, &pid, event, BPF_ANY);
    }
    return 0;
}

// Kprobe for __vma_link_rb
SEC("kprobe/__vma_link_rb")
int BPF_KPROBE(trace_vma_link_rb, struct mm_struct *mm, struct vm_area_struct *vma, struct vm_area_struct *prev, struct rb_node **rb_link, struct rb_node *rb_parent) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    struct insert_event_t *event = bpf_map_lookup_elem(&insert_events, &pid);
    if (event) {
        event->inserted_to_rb = 1;
        event->link_rb_start_time = timestamp;
        bpf_map_update_elem(&insert_events, &pid, event, BPF_ANY);
    }
    return 0;
}

// Kprobe for vma_interval_tree_insert
SEC("kprobe/vma_interval_tree_insert")
int BPF_KPROBE(trace_vma_interval_tree_insert, struct vm_area_struct *vma, struct interval_tree_node *node) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    struct insert_event_t *event = bpf_map_lookup_elem(&insert_events, &pid);
    if (event) {
        event->inserted_to_interval_tree = 1;
        event->interval_tree_start_time = timestamp;
        bpf_map_update_elem(&insert_events, &pid, event, BPF_ANY);
    }
    return 0;
}

// Return probe for insert_vm_struct
SEC("kretprobe/insert_vm_struct")
int BPF_KRETPROBE(trace_insert_vm_struct_ret) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct insert_event_t *event = bpf_map_lookup_elem(&insert_events, &pid);
    if (event) {
        event->duration = bpf_ktime_get_ns() - event->timestamp;

        // Output the result
        bpf_printk("insert_vm_struct duration=%llu ns, list=%d, rb=%d\n",
                   event->duration, event->inserted_to_list,
                   event->inserted_to_rb);
        bpf_printk("interval_tree=%d\n", event->inserted_to_interval_tree);

        // Remove the event after processing
        // bpf_map_delete_elem(&insert_events, &pid);
    }
    return 0;
}

// Return probe for __vma_link_list
SEC("kretprobe/__vma_link_list")
int BPF_KRETPROBE(trace_vma_link_list_ret) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct insert_event_t *event = bpf_map_lookup_elem(&insert_events, &pid);
    if (event) {
        u64 end_time = bpf_ktime_get_ns();
        event->link_list_duration = end_time - event->link_list_start_time;
        bpf_printk("__vma_link_list duration=%llu ns\n", event->link_list_duration);
    }
    return 0;
}

// Return probe for __vma_link_rb
SEC("kretprobe/__vma_link_rb")
int BPF_KRETPROBE(trace_vma_link_rb_ret) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct insert_event_t *event = bpf_map_lookup_elem(&insert_events, &pid);
    if (event) {
        u64 end_time = bpf_ktime_get_ns();
        event->link_rb_duration = end_time - event->link_rb_start_time;
        bpf_printk("__vma_link_rb duration=%llu ns\n", event->link_rb_duration);
    }
    return 0;
}

// Return probe for vma_interval_tree_insert
SEC("kretprobe/vma_interval_tree_insert")
int BPF_KRETPROBE(trace_vma_interval_tree_insert_ret) {
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    struct insert_event_t *event = bpf_map_lookup_elem(&insert_events, &pid);
    if (event) {
        u64 end_time = bpf_ktime_get_ns();
        event->interval_tree_duration = end_time - event->interval_tree_start_time;
        bpf_printk("vma_interval_tree_insert duration=%llu ns\n", event->interval_tree_duration);
    }
    return 0;
}