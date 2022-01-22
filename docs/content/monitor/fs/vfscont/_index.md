+++
title = "插件：fs/vfscont.py"
description = "针对插件：fs/vfscont.py 的分析"
weight = 5
+++

## 插件说明
说明插件的一些基本情况
插件地址： plugins/fs/vfscont.py

## vfscont.py插件分析

插件利用kprobe探针检测内核vfs_.事件。kprobe允许在执行任何内核指令之前插入BPF程序。在这之前，还需要知道插入点的名称。因为内核探针的API不是很稳定，这会导致在不同版本之间相同插件会失效的问题。不过bcc提供了获取系统调用名称的功能：get_syscall_fnname。所以无需记住正在允许的内核版本下该系统调用名。
```
b.attach_kprobe(event_re="^vfs_.*", fn_name="do_count")
```
### BPF映射
BPF程序利用数据映射的形式与用户空间进行数据交互，BPF映射以键/值将数据保存在内核中，它既可以被BPF程序访问，又可以和用户空间程序交互。数据映射分多种类型，该插件使用哈希映射：
```
BPF_HASH(counts, struct key_t, u64, 256);
```

 参数 | 含义  
 ---- | ----  
 counts | 指明映射的键名  
struct |键的数据类型  
u64 | 值的数据类型  
### 插件主体
```
int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    key.ip = PT_REGS_IP(ctx);
    key.timestamp=bpf_ktime_get_ns();
    counts.increment(key);
    return 0;
}
```
 PT_REGS_IP获取函数的ip  

bpf_ktime_get_ns会以纳秒为单位返回系统当前时间。

increment访问下一个键

BPF程序主体如下：
```
b = BPF(text="""
#include <uapi/linux/ptrace.h>

struct key_t {
    u64 ip;
    u64 timestamp;
};

BPF_HASH(counts, struct key_t, u64, 256);

int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    key.ip = PT_REGS_IP(ctx);
    key.timestamp=bpf_ktime_get_ns();
    counts.increment(key);
    return 0;
}
""")
```