// copied from
// https://github.com/merbridge/merbridge/blob/0.7.0/bpf/headers/helpers.h
#pragma once
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h>
#include <linux/swab.h>
#include <linux/types.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_htons(x) (x)
#define bpf_htonl(x) (x)
#else
#error "__BYTE_ORDER__ error"
#endif

#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif

#define PIN_GLOBAL_NS 2

struct bpf_elf_map {
  __u32 type;
  __u32 size_key;
  __u32 size_value;
  __u32 max_elem;
  __u32 flags;
  __u32 id;
  __u32 pinning;
};

struct record {
  __u32 count;
  __u32 fail_count;
  // any request count
  __u32 any_count;
  __u32 padding;
};

struct dns_hdr {
  __u16 id;
  __u16 flags;
  __u16 qdcount;
  __u16 ancount;
  __u16 nscount;
  __u16 arcount;
};

struct dns_question {
  __u32 qname;
  __u16 qtype;
  __u16 qclass;
};

static __u64 (*bpf_get_current_pid_tgid)() = (void *)
    BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_uid_gid)() = (void *)
    BPF_FUNC_get_current_uid_gid;
static void (*bpf_trace_printk)(const char *fmt, int fmt_size,
                                ...) = (void *)BPF_FUNC_trace_printk;
static __u64 (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)
    BPF_FUNC_get_current_comm;

static __u64 (*bpf_get_socket_cookie_ops)(struct bpf_sock_ops *skops) = (void *)
    BPF_FUNC_get_socket_cookie;
static __u64 (*bpf_get_socket_cookie_addr)(struct bpf_sock_addr *ctx) = (void *)
    BPF_FUNC_get_socket_cookie;
static void *(*bpf_map_lookup_elem)(struct bpf_elf_map *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_map_update_elem)(struct bpf_elf_map *map, const void *key,
                                    const void *value, __u64 flags) = (void *)
    BPF_FUNC_map_update_elem;
static __u64 (*bpf_map_delete_elem)(struct bpf_elf_map *map, const void *key) =
    (void *)BPF_FUNC_map_delete_elem;
static struct bpf_sock *(*bpf_sk_lookup_tcp)(
    void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns,
    __u64 flags) = (void *)BPF_FUNC_sk_lookup_tcp;
static struct bpf_sock *(*bpf_sk_lookup_udp)(
    void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns,
    __u64 flags) = (void *)BPF_FUNC_sk_lookup_udp;
static long (*bpf_sk_release)(struct bpf_sock *sock) = (void *)
    BPF_FUNC_sk_release;
static long (*bpf_sock_hash_update)(
    struct bpf_sock_ops *skops, struct bpf_elf_map *map, void *key,
    __u64 flags) = (void *)BPF_FUNC_sock_hash_update;
static long (*bpf_msg_redirect_hash)(
    struct sk_msg_md *md, struct bpf_elf_map *map, void *key,
    __u64 flags) = (void *)BPF_FUNC_msg_redirect_hash;
static long (*bpf_bind)(struct bpf_sock_addr *ctx, struct sockaddr_in *addr,
                        int addr_len) = (void *)BPF_FUNC_bind;
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset,
                                   __u64 from, __u64 to, __u64 flags) = (void *)
    BPF_FUNC_l4_csum_replace;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset,
                                   const void *from, __u32 len, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;

#ifdef PRINTNL
#define PRINT_SUFFIX "\n"
#else
#define PRINT_SUFFIX ""
#endif

#ifndef printk
#define printk(fmt, ...)                                                       \
  ({                                                                           \
    char ____fmt[] = fmt PRINT_SUFFIX;                                         \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })
#endif
