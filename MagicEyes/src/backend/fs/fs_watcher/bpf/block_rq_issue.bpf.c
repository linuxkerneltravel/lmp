#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); 
    __type(key, u32);  // 使用进程 PID 作为键
    __type(value, u64); // I/O 总大小作为值
} io_size_map SEC(".maps");

SEC("tracepoint/block/block_rq_issue")
int tracepoint_block_rq_issue(struct trace_event_raw_block_rq_completion *ctx) {
    struct event_block_rq_issue *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;  // 获取进程 ID
    u64 *size, total_size;

    // 分配 ringbuf 空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;  // 如果分配失败，提前返回
    }

    // 获取当前进程名
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // 填充事件数据
    e->timestamp = bpf_ktime_get_ns();
    e->dev = ctx->dev;  
    e->sector = ctx->sector;  
    e->nr_sectors = ctx->nr_sector;  

    // 日志输出调试信息
    bpf_printk("PID: %u, Sector: %d, nr_sectors: %d\n", pid, ctx->sector, ctx->nr_sector);

    // 查找或初始化该进程的 I/O 总大小
    size = bpf_map_lookup_elem(&io_size_map, &pid);
    if (size) {
        total_size = *size;
    } else {
        total_size = 0;
    }

    // 计算本次 I/O 请求的大小
    const u64 sector_size = 512; // 标准扇区大小
    total_size += ctx->nr_sector * sector_size;

    // 更新 I/O 总大小
    bpf_map_update_elem(&io_size_map, &pid, &total_size, BPF_ANY);

    e->total_io = total_size;

    // 日志输出当前总 I/O 大小
    bpf_printk("Updated Total I/O for PID %u: %llu\n", pid, total_size);

    // 提交事件
    bpf_ringbuf_submit(e, 0);

    return 0;
}