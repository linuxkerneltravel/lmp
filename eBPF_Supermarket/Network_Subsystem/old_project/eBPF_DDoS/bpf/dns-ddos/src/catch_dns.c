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

struct record {
  uint32_t count;
  uint32_t fail_count;
  // any request count
  uint32_t any_count;
  uint32_t padding;
};

BPF_TABLE_PINNED("hash", u8, u32, configuration, 255,
                 "/sys/fs/bpf/xdp/globals/configuration");

BPF_TABLE_PINNED("lru_hash", u32, struct record, counter, 65535,
                 "/sys/fs/bpf/xdp/globals/counter");

BPF_ARRAY(metrics, u64, 16);

BPF_HASH(resp_time, u16, u64);

#define DROP 0
#define PASS -1

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

  if (udp->dport == 53) {
    // request
    // calculate requst size
    __u64 len = udp->length;
    int req_size_key = 0;
    __u64 *size = metrics.lookup(&req_size_key);
    if (size) {
      __sync_fetch_and_add(size, len);
    } else {
      metrics.update(&req_size_key, &len);
    }

    // record request time
    struct dns_hdr_t *dns_hdr = cursor_advance(cursor, sizeof(*dns_hdr));
    __u16 id = dns_hdr->id;
    __u64 time = bpf_ktime_get_ns();
    resp_time.update(&id, &time);
    return PASS;
  }

  if (udp->sport != 53) {
    return PASS;
  }

  // response
  struct dns_hdr_t *dns_hdr = cursor_advance(cursor, sizeof(*dns_hdr));
  __u16 flags = dns_hdr->flags;
  flags &= 15;

  __u32 global_ip = 0;
  struct record *r = counter.lookup(&global_ip);
  if (flags != 0 && r) {
    __sync_fetch_and_add(&r->fail_count, 1);

    __u8 global_fail_threshold_key = 4;
    __u32 *threshold = configuration.lookup(&global_fail_threshold_key);
    if (threshold && r->fail_count >= *threshold) {
      __u8 enforce_tcp_key = 201;
      __u32 enabled = 1;
      configuration.update(&enforce_tcp_key, &enabled);
      bpf_trace_printk("WARNING: under nxdomain attack, enforcing tcp");
    }
  }

  __u32 src_ip = bpf_htonl(ip->dst);
  r = counter.lookup(&src_ip);
  if (!r) {
    return PASS;
  }

  if (flags == 0) {
    // correct, cnt--
    // bpf_trace_printk("dwq rcode 0");
    if (r->fail_count > 0) {
      __sync_fetch_and_add(&r->fail_count, -1);
    }
  } else {
    __sync_fetch_and_add(&r->fail_count, 1);
  }

  // calculate response size
  __u64 len = udp->length;
  int res_size_key = 1;
  __u64 *size = metrics.lookup(&res_size_key);
  if (size) {
    __sync_fetch_and_add(size, len);
  } else {
    metrics.update(&res_size_key, &len);
  }

  // calculate request time
  __u16 id = dns_hdr->id;
  __u64 *start = resp_time.lookup(&id);
  if (start) {
    __u64 time = bpf_ktime_get_ns() - *start;
    int req_time_key = 2;
    __u64 *t = metrics.lookup(&req_time_key);
    if (t) {
      __sync_fetch_and_add(t, time);
    } else {
      metrics.update(&req_time_key, &time);
    }
    resp_time.delete(&id);
  }
  return PASS;
}
