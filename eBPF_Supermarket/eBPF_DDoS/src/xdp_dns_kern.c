#include "common.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/version.h>

struct bpf_elf_map __section("maps") fail_counter = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
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
  __u32 *cnt = bpf_map_lookup_elem(&fail_counter, &src_ip);
  if (cnt) {
    __u32 threshold_key = 0;
    __u32 *threshold = bpf_map_lookup_elem(&fail_counter, &threshold_key);
    if (threshold && *cnt >= *threshold) {
      // printk("dwq xdp dropped, threshold: %d, cnt %d", *threshold, *cnt);
      return XDP_DROP;
    }
    // printk("dwq cnt: %d", *cnt);
  }
  return XDP_PASS;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
