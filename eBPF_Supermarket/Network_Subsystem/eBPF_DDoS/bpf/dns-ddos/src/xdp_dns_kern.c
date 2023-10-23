#include "helpers.h"
#include <linux/if_ether.h>
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

struct bpf_elf_map __section("maps") ddos_programs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u32),
    .max_elem = 63,
    .pinning = PIN_GLOBAL_NS,
};

static __u32 next_prog_idx = 0;

static __always_inline int pass(void *ctx) {
  bpf_tail_call(ctx, &ddos_programs, next_prog_idx);
  return XDP_PASS;
}

__section("xdp") int catch_dns(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = (struct ethhdr *)data;
  if ((void *)(eth + 1) > data_end) {
    return XDP_DROP;
  }
  if (bpf_htons(eth->h_proto) != ETH_P_IP) {
    return pass(ctx);
  }

  struct iphdr *iph = (struct iphdr *)(eth + 1);
  if ((void *)(iph + 1) > data_end) {
    return XDP_DROP;
  }

  __u32 src_ip = iph->saddr;
  struct record *r = bpf_map_lookup_elem(&counter, &src_ip);
  if (r) {
    // drop packets by failure count
    __u8 failure_threshold_key = 0;
    __u32 *threshold =
        bpf_map_lookup_elem(&configuration, &failure_threshold_key);
    if (threshold && r->fail_count >= *threshold) {
      return XDP_DROP;
    }

    // drop packets by total count
    __u8 count_threshold_key = 1;
    threshold = bpf_map_lookup_elem(&configuration, &count_threshold_key);
    if (threshold && r->count >= *threshold) {
      return XDP_DROP;
    }

    // drop packets by any request count
    __u8 any_threshold_key = 2;
    threshold = bpf_map_lookup_elem(&configuration, &any_threshold_key);
    if (threshold && r->any_count >= *threshold) {
      return XDP_DROP;
    }
  }

  if (iph->protocol != IPPROTO_UDP) {
    return pass(ctx);
  }

  struct udphdr *udph = (struct udphdr *)(iph + 1);
  if ((void *)(udph + 1) > data_end) {
    return XDP_DROP;
  }
  if (udph->dest != bpf_htons(53)) {
    return pass(ctx);
  }

  struct dns_hdr *dnsh = (struct dns_hdr *)(udph + 1);
  if ((void *)(dnsh + 1) > data_end) {
    return XDP_DROP;
  }

  __u16 flags = bpf_htons(dnsh->flags);
  if ((flags >> 15) != 0) {
    // not a request.
    return pass(ctx);
  }

  __u8 enforce_tcp_key = 201;
  __u32 *enforce_tcp = bpf_map_lookup_elem(&configuration, &enforce_tcp_key);
  if (enforce_tcp && *enforce_tcp) {
    // set QR=1, TC=1
    dnsh->flags = bpf_htons(flags | 0x8200);
    dnsh->ancount = bpf_htons(1);

    // return the response directly
    __u8 src_mac[6];
    src_mac[0] = eth->h_source[0];
    src_mac[1] = eth->h_source[1];
    src_mac[2] = eth->h_source[2];
    src_mac[3] = eth->h_source[3];
    src_mac[4] = eth->h_source[4];
    src_mac[5] = eth->h_source[5];

    eth->h_source[0] = eth->h_dest[0];
    eth->h_source[1] = eth->h_dest[1];
    eth->h_source[2] = eth->h_dest[2];
    eth->h_source[3] = eth->h_dest[3];
    eth->h_source[4] = eth->h_dest[4];
    eth->h_source[5] = eth->h_dest[5];

    eth->h_dest[0] = src_mac[0];
    eth->h_dest[1] = src_mac[1];
    eth->h_dest[2] = src_mac[2];
    eth->h_dest[3] = src_mac[3];
    eth->h_dest[4] = src_mac[4];
    eth->h_dest[5] = src_mac[5];

    __u32 dst_ip = iph->daddr;
    iph->saddr = dst_ip;
    iph->daddr = src_ip;
    iph->check = iph_csum(iph);

    __u16 src_port = udph->source;
    __u16 dst_port = udph->dest;
    udph->source = dst_port;
    udph->dest = src_port;
    // udph->check = csum_diff4(src_port, dst_port, udph->check);
    // udph->check = csum_diff4(dst_port, src_port, udph->check);
    udph->check = csum_diff4(src_ip, dst_ip, udph->check);
    udph->check = csum_diff4(dst_ip, src_ip, udph->check);
    udph->check = csum_diff4(bpf_htons(flags), dnsh->flags, udph->check);
    udph->check = csum_diff4(0, dnsh->ancount, udph->check);
    return XDP_TX;
  }

  // get qtype
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

  __u32 any = 0;
  if (*(__u16 *)(cursor + 1) == bpf_htons(255)) {
    any = 1;
  }

  __u32 global_ip = 0;
  struct record *global = bpf_map_lookup_elem(&counter, &global_ip);
  if (global) {
    if (any) {
      // drop packets by global any request count
      __u32 global_any_threshold_key = 3;
      __u32 *threshold =
          bpf_map_lookup_elem(&configuration, &global_any_threshold_key);
      if (threshold && global->any_count >= *threshold) {
        return XDP_DROP;
      }
      __sync_fetch_and_add(&global->any_count, 1);
    }
    // update global count
    __sync_fetch_and_add(&global->count, 1);
  } else {
    struct record rec = {
        .count = 1,
        .fail_count = 0,
        .any_count = any,
    };
    bpf_map_update_elem(&counter, &global_ip, &rec, BPF_ANY);
  }

  // update count per ip
  if (r) {
    __sync_fetch_and_add(&r->count, 1);
    if (any) {
      __sync_fetch_and_add(&r->any_count, 1);
    }
  } else {
    struct record rec = {
        .count = 1,
        .fail_count = 0,
        .any_count = any,
    };
    bpf_map_update_elem(&counter, &src_ip, &rec, BPF_ANY);
  }

  return pass(ctx);
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
