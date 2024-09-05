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
// netwatcher libbpf 丢包

#include "common.bpf.h"
static __always_inline
int __tp_kfree(struct trace_event_raw_kfree_skb *ctx)
{
    if(!drop_reason)
        return 0;
    struct sk_buff *skb=ctx->skbaddr;
    if (skb == NULL) // 判断是否为空
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    struct reasonissue  *message;
    message = bpf_ringbuf_reserve(&kfree_rb, sizeof(*message), 0);
    if(!message){
        return 0;
    }
    message->saddr = pkt_tuple.saddr;
    message->daddr = pkt_tuple.daddr;
    message->sport = pkt_tuple.sport;
    message->dport = pkt_tuple.dport;
    message->protocol = ctx->protocol;
    message->location = (long)ctx->location;
    message->drop_reason = ctx->reason;
    bpf_ringbuf_submit(message,0);
    if(stack_info)
        getstack(ctx);
    return 0;
} 