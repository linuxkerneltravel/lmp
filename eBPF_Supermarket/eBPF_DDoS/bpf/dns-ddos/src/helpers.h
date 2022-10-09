// copied from
// https://github.com/merbridge/merbridge/blob/0.7.0/bpf/headers/helpers.h
#pragma once
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h>
#include <linux/ip.h>
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

#ifndef memset
#define memset(dst, src, len) __builtin_memset(dst, src, len)
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

static __u64 (*bpf_tail_call)(void *ctx, struct bpf_elf_map *prog_array_map,
                              __u32 index) = (void *)BPF_FUNC_tail_call;
static __u64 (*bpf_get_current_uid_gid)() = (void *)
    BPF_FUNC_get_current_uid_gid;
static void (*bpf_trace_printk)(const char *fmt, int fmt_size,
                                ...) = (void *)BPF_FUNC_trace_printk;
static void *(*bpf_map_lookup_elem)(struct bpf_elf_map *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_map_update_elem)(struct bpf_elf_map *map, const void *key,
                                    const void *value, __u64 flags) = (void *)
    BPF_FUNC_map_update_elem;
static __u64 (*bpf_map_delete_elem)(struct bpf_elf_map *map, const void *key) =
    (void *)BPF_FUNC_map_delete_elem;
static __u64 (*bpf_perf_event_output)(void *ctx, struct bpf_elf_map *map,
                                      __u64 flags, void *data, __u64 size) =
    (void *)BPF_FUNC_perf_event_output;

static __u64 (*bpf_csum_diff)(__u32 *from, __u32 from_size, __u32 *to,
                              __u32 to_size,
                              __u32 seed) = (void *)BPF_FUNC_csum_diff;

static __always_inline __u16 csum_fold_helper(__u64 csum) {
  int i;
#pragma unroll
  for (i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph) {
  iph->check = 0;
  __u64 csum = bpf_csum_diff(0, 0, (__u32 *)iph, sizeof(struct iphdr), 0);
  return csum_fold_helper(csum);
}

static __always_inline __u32 csum_add(__u32 addend, __u32 csum) {
  __u32 res = csum;
  res += addend;
  return (res + (res < addend));
}

static __always_inline __u32 csum_sub(__u32 addend, __u32 csum) {
  return csum_add(csum, ~addend);
}

static __always_inline __u16 csum_fold_helper4(__u32 csum) {
  __u32 r = csum << 16 | csum >> 16;
  csum = ~csum;
  csum -= r;
  return (__u16)(csum >> 16);
}

static __always_inline __u16 csum_diff4(__u32 from, __u32 to, __u16 csum) {
  __u32 tmp = csum_sub(from, ~((__u32)csum));
  return csum_fold_helper4(csum_add(to, tmp));
}

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
