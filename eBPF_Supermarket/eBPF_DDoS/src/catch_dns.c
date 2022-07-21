#include <bcc/proto.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

struct dns_hdr_t {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} BPF_PACKET_HEADER;

BPF_TABLE_PINNED("lru_hash", u32, u32, fail_counter, 65535,
                 "/sys/fs/bpf/xdp/globals/fail_counter");

#define DROP 0
#define PASS -1.

int catch_dns(struct __sk_buff *skb) {
  u8 *cursor = 0;

  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  if (ethernet->type != ETH_P_IP) {
    return PASS;
  }

  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  if (ip->nextp != IPPROTO_UDP) {
    return PASS;
  }

  struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
  if (udp->sport != 53) {
    return PASS;
  }

  struct dns_hdr_t *dns_hdr = cursor_advance(cursor, sizeof(*dns_hdr));

  __u32 src_ip = bpf_htonl(ip->dst);
  __u32 *cnt = fail_counter.lookup(&src_ip);

  __u16 flags = dns_hdr->flags;
  flags &= 15;
  if (flags == 0) {
    // correct, cnt--
    // bpf_trace_printk("dwq rcode 0");
    if (cnt && *cnt > 0) {
      __sync_fetch_and_add(cnt, -1);
      // bpf_trace_printk("dwq cnt--");
    }
  } else {
    // error, cnt++
    // bpf_trace_printk("dwq rcode %d", flags);
    if (cnt) {
      __sync_fetch_and_add(cnt, 1);
      // bpf_trace_printk("dwq cnt++");
    } else {
      __u32 one = 1;
      fail_counter.update(&src_ip, &one);
      // bpf_trace_printk("dwq cnt=1");
    }
  }
  return PASS;
}
