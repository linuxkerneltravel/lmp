#include "common.h"
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/version.h>

struct bpf_elf_map __section("maps") configuration = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(__u8),
    .size_value = sizeof(__u32),
    .max_elem = 255,
    .pinning = PIN_GLOBAL_NS,
};

struct bpf_elf_map __section("maps") counter = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(__u32),
    .size_value = sizeof(struct record),
    .max_elem = 65535,
    .pinning = PIN_GLOBAL_NS,
};

__section("xdp") int catch_dns(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = (struct ethhdr *)data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_DROP;
  }
  if (bpf_htons(eth->h_proto) != ETH_P_IP) {
    return XDP_PASS;
  }

  struct iphdr *iph = (struct iphdr *)(eth + 1);
  if ((void *)(iph + 1) > data_end) {
    return XDP_DROP;
  }

  __u32 src_ip = iph->saddr;
  struct record *r = bpf_map_lookup_elem(&counter, &src_ip);
  if (r) {
    // drop packets by failure count
    __u32 failure_threshold_key = 0;
    __u32 *threshold =
        bpf_map_lookup_elem(&configuration, &failure_threshold_key);
    if (threshold && r->fail_count >= *threshold) {
      // printk("dwq xdp dropped, threshold: %d, cnt %d", *threshold,
      // r->fail_count);
      return XDP_DROP;
    }
    // printk("dwq cnt: %d", r->fail_count);

    // drop packets by total count
    __u32 count_threshold_key = 1;
    threshold = bpf_map_lookup_elem(&configuration, &count_threshold_key);
    if (threshold && r->count >= *threshold) {
      return XDP_DROP;
    }

    // drop packets by any request count
    __u32 any_threshold_key = 2;
    threshold = bpf_map_lookup_elem(&configuration, &any_threshold_key);
    if (threshold && r->any_count >= *threshold) {
      return XDP_DROP;
    }
  }

  if (iph->protocol != IPPROTO_UDP) {
    return XDP_PASS;
  }

  struct udphdr *udph = (struct udphdr *)(iph + 1);
  if ((void *)(udph + 1) > data_end) {
    return XDP_DROP;
  }
  if (udph->dest != bpf_htons(53)) {
    return XDP_PASS;
  }

  struct dns_hdr *dnsh = (struct dns_hdr *)(udph + 1);
  if ((void *)(dnsh + 1) > data_end) {
    return XDP_DROP;
  }

  if ((dnsh->flags >> 15) != 0) {
    // not a request.
    return XDP_PASS;
  }

  void *cursor = dnsh + 1;
#pragma unroll
  for (__u8 i = 0; i < 20; ++i) {
    if (cursor + 1 > data_end) {
      return XDP_DROP;
    }
    __u8 len = *(__u8 *)(cursor);
    if (len == 0) {
      break;
    }
    if (cursor + len + 1 > data_end) {
      return XDP_DROP;
    }
    cursor += len + 1;
  }

  if (cursor + 5 > data_end) {
    return XDP_DROP;
  }

  //   printk("dwq passed %d %d", *(__u8 *)cursor, *(__u16 *)(cursor + 1));
  //   printk("dwq passed2 %d", *(__u16 *)(cursor + 3));

  __u32 any = 0;
  if (*(__u16 *)(cursor + 1) == bpf_htons(255)) {
    any = 1;
  }

  if (r) {
    __sync_fetch_and_add(&r->count, 1);
    if (any) {
      __sync_fetch_and_add(&r->any_count, any);
    }
  } else {
    struct record rec = {
        .count = 1,
        .fail_count = 0,
        .any_count = any,
    };
    bpf_map_update_elem(&counter, &src_ip, &rec, BPF_ANY);
  }
  return XDP_PASS;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
