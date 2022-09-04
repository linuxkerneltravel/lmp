#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_HLEN 14
#define IP_PROTO_OFF offsetof(struct iphdr, protocol)
#define QDCOUNT_OFF 4

SEC("socket")
int dns_queries(struct __sk_buff *skb) {
  struct iphdr ip4;
  struct udphdr udp;

  if (bpf_ntohs(skb->protocol) != ETH_P_IP)
    return 0;
  if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip4, sizeof(ip4)) < 0)
    return 0;
  if (ip4.ihl != 5 || ip4.protocol != IPPROTO_UDP)
    return 0;

  // load qdcount
  __be16 QDCOUNT = 0;
  if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(ip4) + sizeof(udp) + QDCOUNT_OFF, &QDCOUNT, sizeof(QDCOUNT)) < 0)
    return 0;
  
  QDCOUNT = bpf_ntohs(QDCOUNT);

  if (QDCOUNT == 1)
    return -1;

  return 0;
}

char LICENSE[] SEC("license") = "GPL";