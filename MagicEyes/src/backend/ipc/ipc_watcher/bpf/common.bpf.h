// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// ipcwatcher libbpf 内核<->用户 传递信息相关结构体

#ifndef IPC_IPC_WATCHER_BPF__COMMON_BPF_H
#define IPC_IPC_WATCHER_BPF__COMMON_BPF_H

#include "../include/ipcwatcher.h"

#include "vmlinux.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

/** user option */
const volatile char*  filter_uds_path= NULL;
const volatile int filter_is_exist_path = 1;


#define AF_UNIX		1	/* Unix domain sockets 		*/
#define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
#define PF_UNIX		AF_UNIX
#define PF_LOCAL	AF_LOCAL

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} uds_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, struct sock*);   /** fixme： 怎么唯一标识数据包？ sock? */
    __type(value, struct uds_event);
} uds_data_map SEC(".maps");

// 操作BPF映射的一个辅助函数
static __always_inline void * //__always_inline强制内联
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
    void *val;
    long err;

    val = bpf_map_lookup_elem(map, key); // 在BPF映射中查找具有给定键的条目
    if (val)
        return val;
    // 此时没有对应key的value
    err = bpf_map_update_elem(map, key, init,
                              BPF_NOEXIST); // 向BPF映射中插入或更新一个条目
    if (err && err != -EEXIST)              // 插入失败
        return 0;

    return bpf_map_lookup_elem(map, key); // 返回对应value值
}


#define FILTER                                                                 \
    if (filter_dport && filter_dport != pkt_tuple.dport)                       \
        return 0;                                                              \
    if (filter_sport && filter_sport != pkt_tuple.sport)                       \
        return 0;

// 连接的目标端口是否匹配于filter_dport的值
#define FILTER_DPORT                                                           \
    if (filter_dport) {                                                        \
        if (conn.dport != filter_dport) {                                      \
            return 0;                                                          \
        }                                                                      \
    }
// 连接的源端口是否匹配于filter_sport的值
#define FILTER_SPORT                                                           \
    if (filter_sport) {                                                        \
        if (conn.sport != filter_sport) {                                      \
            return 0;                                                          \
        }                                                                      \
    }

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = val)

/* help functions */
// 将struct sock类型的指针转化为struct tcp_sock类型的指针
static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk) {
    return (struct tcp_sock *)sk;
}
// 将struct sk_buff类型的指针转化为struct udphdr类型的指针
static __always_inline struct udphdr *skb_to_udphdr(const struct sk_buff *skb) {
    return (struct udphdr *)((
        BPF_CORE_READ(skb, head) +              // 报文头部偏移
        BPF_CORE_READ(skb, transport_header))); // 传输层部分偏移
}
// 将struct sk_buff类型的指针转化为struct tcphdr类型的指针
static __always_inline struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb) {
    return (struct tcphdr *)((
        BPF_CORE_READ(skb, head) +              // 报文头部偏移
        BPF_CORE_READ(skb, transport_header))); // 传输层部分偏移
}
// 将struct sk_buff类型的指针转化为struct iphdr类型的指针
static __always_inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb) {
    return (struct iphdr *)(BPF_CORE_READ(skb, head) +
                            BPF_CORE_READ(skb, network_header));
}

#if KERNEL_VERSION(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH) >=             \
    KERNEL_VERSION(6, 3, 1)
#define GET_USER_DATA(msg) BPF_CORE_READ(msg, msg_iter.__iov, iov_base)
#else
#define GET_USER_DATA(msg) BPF_CORE_READ(msg, msg_iter.iov, iov_base)
#endif


#endif   // IPC_IPC_WATCHER_BPF__COMMON_BPF_H
