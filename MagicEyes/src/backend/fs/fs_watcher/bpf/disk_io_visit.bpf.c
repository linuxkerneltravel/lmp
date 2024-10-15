#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义 ringbuf，用于传输事件信息
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

// 这里挂载点得是这个struct trace_event_raw_block_rq_completion *ctx
SEC("tracepoint/block/block_rq_complete")
int tracepoint_block_visit(struct trace_event_raw_block_rq_completion *ctx) {
    struct event_disk_io_visit  *e;
    u32 *count, new_count;
    char comm[TASK_COMM_LEN];

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
        return 0;  // 如果分配失败，提前返回
    }

    // 填充事件数据
    e->timestamp = bpf_ktime_get_ns();
    e->blk_dev = ctx->dev;  // 直接读取块设备号
    e->sectors = ctx->nr_sector;  // 读取操作的扇区数

    // 判断读写标识符 (检查 rwbs 数组的内容)
    if (ctx->rwbs[0] == 'R') {
        e->rwbs = 1;  // 1 表示读操作
    } else {
        e->rwbs = 0;  // 0 表示写操作
    }

    // 更新 I/O 操作计数
    e->count = new_count;

    // 复制进程名
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    bpf_printk("comm : %s\n",e->comm);

    // 提交事件
    bpf_ringbuf_submit(e, 0);

    return 0;
}