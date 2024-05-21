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
// netwatcher libbpf icmp

#include "common.bpf.h"

static __always_inline
int __icmp_time(struct sk_buff *skb)
{
    if(!icmp_info||skb==NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct ip_packet ipk = {0};
    get_ip_pkt_tuple(&ipk, ip);
    unsigned long long time= bpf_ktime_get_ns() / 1000;
    bpf_map_update_elem(&icmp_time, &ipk, &time, BPF_ANY);
    return 0;
}

static __always_inline
int __rcvend_icmp_time(struct sk_buff *skb)
{
    if(!icmp_info)
        return 0;
    if(skb==NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct ip_packet ipk = {0};
    get_ip_pkt_tuple(&ipk, ip);
    unsigned long long *pre_time = bpf_map_lookup_elem(&icmp_time, &ipk);
    if(pre_time==NULL)
        return 0;
    
    unsigned long long new_time= bpf_ktime_get_ns() / 1000;
    unsigned long long time=new_time-*pre_time;
    struct icmptime *message;
    message = bpf_ringbuf_reserve(&icmp_rb, sizeof(*message), 0);
    if(!message){
        return 0;
    }

    message->saddr = ipk.saddr;
    message->daddr =ipk.daddr;
    message->icmp_tran_time =time; 
    message->flag =0; 
    bpf_ringbuf_submit(message,0);
    return 0;
}

static __always_inline
int __reply_icmp_time(struct sk_buff *skb)
{
    if(!icmp_info)
        return 0;
    if(skb==NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct ip_packet ipk = {0};
    get_ip_pkt_tuple(&ipk, ip);
    unsigned long long *pre_time = bpf_map_lookup_elem(&icmp_time, &ipk);
    if(pre_time==NULL)
        return 0;
    unsigned long long new_time= bpf_ktime_get_ns() / 1000;
    unsigned long long time=new_time-*pre_time;
    struct icmptime *message;
    message = bpf_ringbuf_reserve(&icmp_rb, sizeof(*message), 0);
    if(!message){
        return 0;
    }

    message->saddr = ipk.saddr;
    message->daddr =ipk.daddr;
    message->icmp_tran_time =time; 
    message->flag =1; 
    bpf_ringbuf_submit(message,0);
    return 0;
}