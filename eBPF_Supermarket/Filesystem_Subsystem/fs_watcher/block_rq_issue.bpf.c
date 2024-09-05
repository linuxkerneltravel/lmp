#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "block_rq_issue.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义 ringbuf，用于传输事件信息
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 这里挂载点必须是struct trace_event_raw_block_rq_completion *ctx
SEC("tracepoint/block/block_rq_issue")
int tracepoint_block_rq_issue(struct trace_event_raw_block_rq_completion *ctx) {
    struct event *e;
    char comm[TASK_COMM_LEN];

    // 分配 ringbuf 空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;  // 如果分配失败，提前返回
    }

    // 填充事件数据
    e->timestamp = bpf_ktime_get_ns();
    e->dev = ctx->dev;  // 读取设备号
    e->sector = ctx->sector;  // 读取扇区号
    e->nr_sectors = ctx->nr_sector;  // 读取扇区数

    // 获取进程名
    bpf_get_current_comm(comm, sizeof(comm));
    __builtin_memcpy(e->comm, comm, sizeof(comm));

    // 提交事件
    bpf_ringbuf_submit(e, 0);

    return 0;
}
