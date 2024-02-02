// syscall_count_kern.c
#include "vmlinux.h"
#include "bpf/bpf_helpers.h"

// 大小为1的数组，用于存放计数值
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} data SEC(".maps");

// 不需要处理参数默认直接 void* 指针即可
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_enter_open(void *arg) {
    u32 key = 0;
    u32 init_val = 0;
    // 查找arr[0]并+1，不存在则创建
    u32 *value = bpf_map_lookup_elem(&data, &key);
    if (value) {
        *value += 1;
    } else {
        bpf_map_update_elem(&data, &key, &init_val, BPF_NOEXIST);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";