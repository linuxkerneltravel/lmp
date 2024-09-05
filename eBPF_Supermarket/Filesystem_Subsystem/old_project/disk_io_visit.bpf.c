#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "disk_io_visit.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 进程名与 I/O 计数映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, u32);
} io_count_map SEC(".maps");

SEC("tracepoint/block/block_rq_complete")
int tracepoint_block_visit(struct trace_event_raw_block_rq_complete *ctx) {
    struct event *e;
    u32 *count, new_count;
    char comm[TASK_COMM_LEN];
    unsigned long long ts;

    // 获取当前进程名
    bpf_get_current_comm(comm, sizeof(comm));

    // 查找或初始化该进程的I/O计数
    count = bpf_map_lookup_elem(&io_count_map, comm);
    if (count) {
        new_count = *count + 1;
    } else {
        new_count = 1;
    }
    bpf_map_update_elem(&io_count_map, comm, &new_count, BPF_ANY);

    // 分配 ringbuf 空间
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // 填充事件数据
    ts= bpf_ktime_get_ns();
    e->timestamp = ts;
    e->blk_dev = ctx->dev;
    e->sectors = ctx->nr_sector;
    e->rwbs = (ctx->rwbs[0] == 'R') ? 1 : 0;
    e->count = new_count;
    __builtin_memcpy(e->comm, comm, sizeof(comm));

    // 提交事件
    bpf_ringbuf_submit(e, 0);
    return 0;
}
