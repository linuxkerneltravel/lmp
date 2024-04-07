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
// author: blown.away@qq.com

#include "common.bpf.h"

static __always_inline
int __udp_rcv(struct sk_buff *skb)
{
    if (!udp_info||skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct udphdr *udp = skb_to_udphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_udp_pkt_tuple(&pkt_tuple, ip, udp);
    struct ktime_info *tinfo, zero = {0};
    tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&timestamps,
                                                            &pkt_tuple, &zero);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->tran_time = bpf_ktime_get_ns() / 1000;
    return 0;
}
static __always_inline
int udp_enqueue_schedule_skb(struct sock *sk,struct sk_buff *skb)
{
    if (!udp_info||skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct udphdr *udp = skb_to_udphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    pkt_tuple.daddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    pkt_tuple.saddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    pkt_tuple.dport = BPF_CORE_READ(sk, __sk_common.skc_num);
    pkt_tuple.sport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    pkt_tuple.tran_flag = UDP ;
    struct ktime_info *tinfo, zero = {0};
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    struct udp_message *message;
    struct udp_message *udp_message =
        bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    message = bpf_ringbuf_reserve(&udp_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }
    message->saddr =  pkt_tuple.saddr;
    message->daddr =  pkt_tuple.daddr;
    message->dport =  pkt_tuple.sport;
    message->sport =  pkt_tuple.dport;
    message->tran_time = bpf_ktime_get_ns() / 1000 - tinfo->tran_time;
    message->rx=1;//收包
    message->len=__bpf_ntohs(BPF_CORE_READ(udp,len));
    bpf_ringbuf_submit(message, 0);
    return 0;
}


static __always_inline
int __udp_send_skb(struct sk_buff *skb)
{
    if (!udp_info||skb==NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct udphdr *udp = skb_to_udphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_udp_pkt_tuple(&pkt_tuple, ip, udp);
    struct ktime_info *tinfo, zero = {0};
    tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&timestamps,
                                                         &pkt_tuple, &zero);
    if (tinfo == NULL) {
        return 0;
    }
    tinfo->tran_time = bpf_ktime_get_ns() / 1000;
   
    return 0;
}
static __always_inline
int __ip_send_skb(struct sk_buff *skb)
{
    if (!udp_info||skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct udphdr *udp = skb_to_udphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_udp_pkt_tuple(&pkt_tuple, ip, udp);
  //  bpf_printk("%d %d",pkt_tuple.saddr,pkt_tuple.daddr);
    struct sock *sk = BPF_CORE_READ(skb, sk);
    pkt_tuple.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    pkt_tuple.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    pkt_tuple.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    pkt_tuple.dport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    pkt_tuple.tran_flag = UDP;
    struct ktime_info *tinfo, zero = {0};
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL) {
        return 0;
    }
    struct udp_message *message;
    struct udp_message *udp_message =bpf_map_lookup_elem(&timestamps,&pkt_tuple);
    message = bpf_ringbuf_reserve(&udp_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }
    message->tran_time = bpf_ktime_get_ns() / 1000 - tinfo->tran_time;
    message->saddr =  pkt_tuple.saddr;
    message->daddr =  pkt_tuple.daddr;
    message->sport =  pkt_tuple.sport;
    message->dport =  pkt_tuple.dport;
    message->rx=0;//发包
    message->len=__bpf_ntohs(BPF_CORE_READ(udp,len));
    bpf_ringbuf_submit(message, 0);
    return 0;
}
